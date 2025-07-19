package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"v2ray-stat/api"
	"v2ray-stat/config"
	"v2ray-stat/constant"
	"v2ray-stat/db"
	"v2ray-stat/logger"
	"v2ray-stat/manager"
	"v2ray-stat/stats"

	_ "github.com/mattn/go-sqlite3"
)

var (
	uniqueEntries       = make(map[string]map[string]time.Time)
	uniqueEntriesMutex  sync.Mutex
	previousStats       string
	clientPreviousStats string
	isInactive          = make(map[string]bool)
	isInactiveMutex     sync.Mutex
	timeLocation        *time.Location
)

func initTimezone(cfg *config.Config) {
	if cfg.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			cfg.Logger.Warn("Некорректная TIMEZONE, используется системная", "timezone", cfg.Timezone, "error", err)
			timeLocation = time.Local
		} else {
			timeLocation = loc
		}
	} else {
		timeLocation = time.Local
		cfg.Logger.Info("Используется системная TIMEZONE", "timezone", time.Local.String())
	}
}

func extractProxyTraffic(apiData *api.ApiResponse) []string {
	var result []string
	for _, stat := range apiData.Stat {
		if strings.Contains(stat.Name, "user") || strings.Contains(stat.Name, "api") || strings.Contains(stat.Name, "block") {
			continue
		}
		parts := splitAndCleanName(stat.Name)
		if len(parts) > 0 {
			result = append(result, fmt.Sprintf("%s %s", strings.Join(parts, " "), stat.Value))
		}
	}
	return result
}

func extractUserTraffic(apiData *api.ApiResponse) []string {
	var result []string
	for _, stat := range apiData.Stat {
		if strings.Contains(stat.Name, "user") {
			parts := splitAndCleanName(stat.Name)
			if len(parts) > 0 {
				result = append(result, fmt.Sprintf("%s %s", strings.Join(parts, " "), stat.Value))
			}
		}
	}
	return result
}

func splitAndCleanName(name string) []string {
	parts := strings.Split(name, ">>>")
	if len(parts) == 4 {
		return []string{parts[1], parts[3]}
	}
	return nil
}

func updateProxyStats(manager *manager.DatabaseManager, apiData *api.ApiResponse, cfg *config.Config) {
	currentStats := extractProxyTraffic(apiData)
	if previousStats == "" {
		previousStats = strings.Join(currentStats, "\n")
		cfg.Logger.Debug("Инициализация previousStats", "stats_count", len(currentStats))
		return
	}

	currentValues := make(map[string]int)
	previousValues := make(map[string]int)

	for _, line := range currentStats {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			currentValues[parts[0]+" "+parts[1]] = stringToInt(cfg, parts[2])
		} else {
			cfg.Logger.Warn("Неверный формат строки статистики", "line", line)
		}
	}

	previousLines := strings.SplitSeq(previousStats, "\n")
	for line := range previousLines {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			previousValues[parts[0]+" "+parts[1]] = stringToInt(cfg, parts[2])
		}
	}

	uplinkValues := make(map[string]int)
	downlinkValues := make(map[string]int)
	sessUplinkValues := make(map[string]int)
	sessDownlinkValues := make(map[string]int)

	for key, current := range currentValues {
		previous, exists := previousValues[key]
		if !exists {
			previous = 0
		}
		diff := max(current-previous, 0)
		parts := strings.Fields(key)
		source := parts[0]
		direction := parts[1]

		switch direction {
		case "uplink":
			uplinkValues[source] = diff
			sessUplinkValues[source] = current
		case "downlink":
			downlinkValues[source] = diff
			sessDownlinkValues[source] = current
		}
	}

	err := manager.Execute(func(db *sql.DB) error {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		for source := range uplinkValues {
			uplink := uplinkValues[source]
			downlink := downlinkValues[source]
			sessUplink := sessUplinkValues[source]
			sessDownlink := sessDownlinkValues[source]
			previousUplink, uplinkExists := previousValues[source+" uplink"]
			previousDownlink, downlinkExists := previousValues[source+" downlink"]

			if !uplinkExists {
				previousUplink = 0
			}
			if !downlinkExists {
				previousDownlink = 0
			}

			uplinkOnline := max(sessUplink-previousUplink, 0)
			downlinkOnline := max(sessDownlink-previousDownlink, 0)
			rate := (uplinkOnline + downlinkOnline) * 8 / cfg.V2rayStat.Monitor.TickerInterval

			cfg.Logger.Debug("Обновление статистики для источника", "source", source, "rate", rate, "uplink", uplink, "downlink", downlink)

			_, err := tx.Exec(`
				INSERT INTO traffic_stats (source, rate, uplink, downlink, sess_uplink, sess_downlink)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT(source) DO UPDATE SET
					rate = ?,
					uplink = uplink + ?,
					downlink = downlink + ?,
					sess_uplink = ?,
					sess_downlink = ?`,
				source, rate, uplink, downlink, sessUplink, sessDownlink,
				rate, uplink, downlink, sessUplink, sessDownlink)
			if err != nil {
				return fmt.Errorf("ошибка выполнения запроса для %s: %v", source, err)
			}
		}

		return tx.Commit()
	})
	if err != nil {
		cfg.Logger.Error("Ошибка SQL в updateProxyStats", "error", err)
		return
	}
	previousStats = strings.Join(currentStats, "\n")
	cfg.Logger.Debug("Статистика прокси обновлена", "stats_count", len(currentStats))
}

func updateClientStats(manager *manager.DatabaseManager, apiData *api.ApiResponse, cfg *config.Config) {
	clientCurrentStats := extractUserTraffic(apiData)
	if clientPreviousStats == "" {
		clientPreviousStats = strings.Join(clientCurrentStats, "\n")
		cfg.Logger.Debug("Инициализация clientPreviousStats", "stats_count", len(clientCurrentStats))
		return
	}

	clientCurrentValues := make(map[string]int)
	clientPreviousValues := make(map[string]int)

	for _, line := range clientCurrentStats {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			clientCurrentValues[parts[0]+" "+parts[1]] = stringToInt(cfg, parts[2])
		} else {
			cfg.Logger.Warn("Неверный формат строки клиентской статистики", "line", line)
		}
	}

	previousLines := strings.SplitSeq(clientPreviousStats, "\n")
	for line := range previousLines {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			clientPreviousValues[parts[0]+" "+parts[1]] = stringToInt(cfg, parts[2])
		}
	}

	clientUplinkValues := make(map[string]int)
	clientDownlinkValues := make(map[string]int)
	clientSessUplinkValues := make(map[string]int)
	clientSessDownlinkValues := make(map[string]int)

	for key, current := range clientCurrentValues {
		previous, exists := clientPreviousValues[key]
		if !exists {
			previous = 0
		}
		diff := max(current-previous, 0)
		parts := strings.Fields(key)
		user := parts[0]
		direction := parts[1]

		switch direction {
		case "uplink":
			clientUplinkValues[user] = diff
			clientSessUplinkValues[user] = current
		case "downlink":
			clientDownlinkValues[user] = diff
			clientSessDownlinkValues[user] = current
		}
	}

	for key := range clientPreviousValues {
		parts := strings.Fields(key)
		if len(parts) != 2 {
			continue
		}
		user := parts[0]
		direction := parts[1]

		switch direction {
		case "uplink":
			if _, exists := clientSessUplinkValues[user]; !exists {
				clientSessUplinkValues[user] = 0
				clientUplinkValues[user] = 0
			}
		case "downlink":
			if _, exists := clientSessDownlinkValues[user]; !exists {
				clientSessDownlinkValues[user] = 0
				clientDownlinkValues[user] = 0
			}
		}
	}

	currentTime := time.Now().In(timeLocation)
	err := manager.Execute(func(db *sql.DB) error {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		isInactiveMutex.Lock()
		defer isInactiveMutex.Unlock()

		for user := range clientUplinkValues {
			uplink := clientUplinkValues[user]
			downlink := clientDownlinkValues[user]
			sessUplink := clientSessUplinkValues[user]
			sessDownlink := clientSessDownlinkValues[user]
			previousUplink, uplinkExists := clientPreviousValues[user+" uplink"]
			previousDownlink, downlinkExists := clientPreviousValues[user+" downlink"]

			if !uplinkExists {
				previousUplink = 0
			}
			if !downlinkExists {
				previousDownlink = 0
			}

			uplinkOnline := max(sessUplink-previousUplink, 0)
			downlinkOnline := max(sessDownlink-previousDownlink, 0)
			rate := (uplinkOnline + downlinkOnline) * 8 / cfg.V2rayStat.Monitor.TickerInterval

			cfg.Logger.Debug("Обновление статистики для клиента", "user", user, "rate", rate, "uplink", uplink, "downlink", downlink)

			var lastSeen string
			if rate > cfg.V2rayStat.Monitor.OnlineRateThreshold*1000 {
				lastSeen = "online"
				isInactive[user] = false
			} else {
				if !isInactive[user] {
					lastSeen = currentTime.Truncate(time.Minute).Format("2006-01-02 15:04")
					isInactive[user] = true
				}
			}

			if lastSeen != "" {
				_, err := tx.Exec(`
					INSERT INTO clients_stats (user, last_seen, rate, uplink, downlink, sess_uplink, sess_downlink)
					VALUES (?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT(user) DO UPDATE SET
						last_seen = ?,
						rate = ?,
						uplink = uplink + ?,
						downlink = downlink + ?,
						sess_uplink = ?,
						sess_downlink = ?`,
					user, lastSeen, rate, uplink, downlink, sessUplink, sessDownlink,
					lastSeen, rate, uplink, downlink, sessUplink, sessDownlink)
				if err != nil {
					return fmt.Errorf("ошибка выполнения запроса для %s: %v", user, err)
				}
			} else {
				_, err := tx.Exec(`
					INSERT INTO clients_stats (user, rate, uplink, downlink, sess_uplink, sess_downlink)
					VALUES (?, ?, ?, ?, ?, ?)
					ON CONFLICT(user) DO UPDATE SET
						rate = ?,
						uplink = uplink + ?,
						downlink = downlink + ?,
						sess_uplink = ?,
						sess_downlink = ?`,
					user, rate, uplink, downlink, sessUplink, sessDownlink,
					rate, uplink, downlink, sessUplink, sessDownlink)
				if err != nil {
					return fmt.Errorf("ошибка выполнения запроса для %s: %v", user, err)
				}
			}
		}

		return tx.Commit()
	})
	if err != nil {
		cfg.Logger.Error("Ошибка SQL в updateClientStats", "error", err)
		return
	}

	clientPreviousStats = strings.Join(clientCurrentStats, "\n")
	cfg.Logger.Debug("Статистика клиентов обновлена", "stats_count", len(clientCurrentStats))
}

func stringToInt(cfg *config.Config, s string) int {
	result, err := strconv.Atoi(s)
	if err != nil {
		cfg.Logger.Warn("Ошибка преобразования строки в число", "string", s, "error", err)
		return 0
	}
	return result
}

func processLogLine(line string, dnsStats map[string]map[string]int, cfg *config.Config) (string, []string, bool) {
	matches := regexp.MustCompile(cfg.Core.AccessLogRegex).FindStringSubmatch(line)
	if len(matches) != 3 && len(matches) != 4 {
		cfg.Logger.Debug("Пропущена строка лога, не соответствует regex", "line", line)
		return "", nil, false
	}

	var user, domain, ip string
	if len(matches) == 4 {
		ip = matches[1]
		domain = strings.TrimSpace(matches[2])
		user = strings.TrimSpace(matches[3])
	} else {
		user = strings.TrimSpace(matches[1])
		ip = strings.TrimSpace(matches[2])
		domain = ""
	}

	uniqueEntriesMutex.Lock()
	if uniqueEntries[user] == nil {
		uniqueEntries[user] = make(map[string]time.Time)
	}
	uniqueEntries[user][ip] = time.Now()

	validIPs := []string{}
	for ip, timestamp := range uniqueEntries[user] {
		if time.Since(timestamp) <= 66*time.Second {
			validIPs = append(validIPs, ip)
		}
	}
	uniqueEntriesMutex.Unlock()

	if dnsStats[user] == nil {
		dnsStats[user] = make(map[string]int)
	}
	if domain != "" {
		dnsStats[user][domain]++
	}

	cfg.Logger.Trace("Обработана строка лога", "user", user, "ip", ip, "domain", domain)
	return user, validIPs, true
}

func readNewLines(manager *manager.DatabaseManager, file *os.File, offset *int64, cfg *config.Config) {
	file.Seek(*offset, 0)
	scanner := bufio.NewScanner(file)

	dnsStats := make(map[string]map[string]int)
	ipUpdates := make(map[string][]string)

	for scanner.Scan() {
		user, validIPs, ok := processLogLine(scanner.Text(), dnsStats, cfg)
		if ok {
			ipUpdates[user] = validIPs
		}
	}

	if err := scanner.Err(); err != nil {
		cfg.Logger.Error("Ошибка чтения файла логов", "error", err)
		return
	}

	for user, validIPs := range ipUpdates {
		if err := db.UpdateIPInDB(manager, user, validIPs); err != nil {
			cfg.Logger.Error("Ошибка обновления IP в базе данных", "user", user, "error", err)
			return
		}
	}

	if len(dnsStats) > 0 {
		if err := db.UpsertDNSRecordsBatch(manager, dnsStats); err != nil {
			cfg.Logger.Error("Ошибка обновления dns_stats", "error", err)
			return
		}
	}

	pos, err := file.Seek(0, 1)
	if err != nil {
		cfg.Logger.Error("Ошибка получения позиции файла", "error", err)
		return
	}
	*offset = pos
	cfg.Logger.Debug("Обработаны новые строки лога", "offset", pos)
}

func monitorUsersAndLogs(ctx context.Context, manager *manager.DatabaseManager, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		accessLog, err := os.OpenFile(cfg.Core.AccessLog, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			cfg.Logger.Error("Ошибка открытия файла логов", "file", cfg.Core.AccessLog, "error", err)
			return
		}
		defer accessLog.Close()

		var accessOffset int64
		accessLog.Seek(0, 2)
		accessOffset, err = accessLog.Seek(0, 1)
		if err != nil {
			cfg.Logger.Error("Ошибка получения позиции файла логов", "error", err)
			return
		}
		cfg.Logger.Info("Инициализация мониторинга логов", "file", cfg.Core.AccessLog, "offset", accessOffset)

		ticker := time.NewTicker(time.Duration(cfg.V2rayStat.Monitor.TickerInterval) * time.Second)
		defer ticker.Stop()

		dailyTicker := time.NewTicker(24 * time.Hour)
		defer dailyTicker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := db.AddUserToDB(manager, cfg); err != nil {
					cfg.Logger.Error("Ошибка добавления пользователей", "error", err)
				}
				if err := db.DelUserFromDB(manager, cfg); err != nil {
					cfg.Logger.Error("Ошибка удаления пользователей", "error", err)
				}

				apiData, err := api.GetApiResponse(cfg)
				if err != nil {
					cfg.Logger.Error("Ошибка получения данных API", "error", err)
				} else {
					updateProxyStats(manager, apiData, cfg)
					updateClientStats(manager, apiData, cfg)
				}
				readNewLines(manager, accessLog, &accessOffset, cfg)

			case <-dailyTicker.C:
				if err := accessLog.Close(); err != nil {
					cfg.Logger.Error("Ошибка при закрытии файла логов", "file", cfg.Core.AccessLog, "error", err)
				}
				accessLog, err = os.OpenFile(cfg.Core.AccessLog, os.O_RDONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					cfg.Logger.Error("Ошибка при открытии файла логов после очистки", "file", cfg.Core.AccessLog, "error", err)
					return
				}
				accessOffset = 0
				cfg.Logger.Info("Файл логов успешно очищен", "file", cfg.Core.AccessLog)

			case <-ctx.Done():
				cfg.Logger.Info("Мониторинг логов остановлен")
				return
			}
		}
	}()
}

func withServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHeader := fmt.Sprintf("MuxCloud/%s (WebServer)", constant.Version)
		w.Header().Set("Server", serverHeader)
		w.Header().Set("X-Powered-By", "MuxCloud")
		next.ServeHTTP(w, r)
	})
}

func startAPIServer(ctx context.Context, manager *manager.DatabaseManager, cfg *config.Config, wg *sync.WaitGroup) {
	server := &http.Server{
		Addr:    cfg.V2rayStat.Address + ":" + cfg.V2rayStat.Port,
		Handler: withServerHeader(http.DefaultServeMux),
	}

	http.HandleFunc("/", api.Answer())
	http.HandleFunc("/api/v1/users", api.UsersHandler(manager))
	http.HandleFunc("/api/v1/stats", api.StatsCustomHandler(manager, cfg))
	http.HandleFunc("/api/v1/stats/base", api.StatsHandler(manager, cfg))
	http.HandleFunc("/api/v1/dns_stats", api.DnsStatsHandler(manager))
	http.HandleFunc("/api/v1/add_user", api.TokenAuthMiddleware(cfg, api.AddUserHandler(cfg)))
	http.HandleFunc("/api/v1/bulk_add_users", api.TokenAuthMiddleware(cfg, api.BulkAddUsersHandler(cfg)))
	http.HandleFunc("/api/v1/delete_user", api.TokenAuthMiddleware(cfg, api.DeleteUserHandler(cfg)))
	http.HandleFunc("/api/v1/set_enabled", api.TokenAuthMiddleware(cfg, api.SetEnabledHandler(manager, cfg)))
	http.HandleFunc("/api/v1/update_lim_ip", api.TokenAuthMiddleware(cfg, api.UpdateIPLimitHandler(manager)))
	http.HandleFunc("/api/v1/adjust_date", api.TokenAuthMiddleware(cfg, api.AdjustDateOffsetHandler(manager, cfg)))
	http.HandleFunc("/api/v1/update_renew", api.TokenAuthMiddleware(cfg, api.UpdateRenewHandler(manager)))
	http.HandleFunc("/api/v1/delete_dns_stats", api.TokenAuthMiddleware(cfg, api.DeleteDNSStatsHandler(manager)))
	http.HandleFunc("/api/v1/reset_traffic", api.TokenAuthMiddleware(cfg, api.ResetTrafficHandler()))
	http.HandleFunc("/api/v1/reset_clients_stats", api.TokenAuthMiddleware(cfg, api.ResetClientsStatsHandler(manager)))
	http.HandleFunc("/api/v1/reset_traffic_stats", api.TokenAuthMiddleware(cfg, api.ResetTrafficStatsHandler(manager)))

	cfg.Logger.Info("Запуск API-сервера", "address", server.Addr)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			cfg.Logger.Fatal("Ошибка запуска сервера", "error", err)
		}
	}()

	<-ctx.Done()

	cfg.Logger.Info("Остановка API-сервера")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		cfg.Logger.Error("Ошибка остановки сервера", "error", err)
	}
	wg.Done()
}

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		logger, _ := logger.NewLogger("error", os.Stderr)
		logger.Fatal("Ошибка загрузки конфигурации", "error", err)
	}
	initTimezone(&cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	memDB, fileDB, err := db.InitDatabase(&cfg)
	if err != nil {
		cfg.Logger.Fatal("Ошибка инициализации базы данных", "error", err)
	}
	defer memDB.Close()
	defer fileDB.Close()

	manager, err := manager.NewDatabaseManager(memDB, ctx, 2, 50, 100, &cfg)
	if err != nil {
		cfg.Logger.Fatal("Ошибка создания DatabaseManager", "error", err)
	}

	isInactive, err = db.LoadIsInactiveFromLastSeen(manager)
	if err != nil {
		cfg.Logger.Fatal("Ошибка загрузки начального статуса", "error", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	wg.Add(1)
	go startAPIServer(ctx, manager, &cfg, &wg)
	monitorUsersAndLogs(ctx, manager, &cfg, &wg)

	if cfg.Features["network"] {
		if err := stats.InitNetworkMonitoring(); err != nil {
			cfg.Logger.Error("Ошибка инициализации мониторинга сети", "error", err)
		}
		stats.MonitorNetwork(ctx, &cfg, &wg)
	}

	if cfg.Features["telegram"] {
		stats.MonitorDailyReport(ctx, manager, &cfg, &wg)
		stats.MonitorStats(ctx, &cfg, &wg)
	}

	log.Printf("Starting v2ray-stat application %s, with core: %s", constant.Version, cfg.V2rayStat.Type)

	<-sigChan
	cfg.Logger.Info("Получен сигнал завершения, сохранение данных")
	cancel()
	wg.Wait()

	// Используем новый контекст для финальной синхронизации с увеличенным таймаутом
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer syncCancel()
	if err := manager.SyncDBWithContext(syncCtx, fileDB, "memory to file"); err != nil {
		cfg.Logger.Error("Ошибка финальной синхронизации базы данных", "error", err)
	}

	// Закрытие менеджера
	manager.Close()
	cfg.Logger.Info("Программа завершена")
}

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
	"v2ray-stat/monitor"
	"v2ray-stat/stats"

	_ "github.com/mattn/go-sqlite3"
)

var (
	uniqueEntries       = make(map[string]map[string]time.Time)
	uniqueEntriesMutex  sync.Mutex
	dbMutex             sync.Mutex
	previousStats       string
	clientPreviousStats string
)

var (
	accessLogRegex = regexp.MustCompile(`from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`)
)

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

func updateProxyStats(memDB *sql.DB, apiData *api.ApiResponse) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if !CheckTableExists(memDB, "traffic_stats") {
		log.Printf("Table traffic_stats does not exist, reinitializing database")
		if err := db.InitDB(memDB); err != nil {
			log.Printf("Failed to reinitialize database: %v", err)
			return
		}
	}

	currentStats := extractProxyTraffic(apiData)

	if previousStats == "" {
		previousStats = strings.Join(currentStats, "\n")
	}

	currentValues := make(map[string]int)
	previousValues := make(map[string]int)

	for _, line := range currentStats {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			currentValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
		} else {
			log.Printf("Error: invalid line format: %s", line)
		}
	}

	previousLines := strings.Split(previousStats, "\n")
	for _, line := range previousLines {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			previousValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
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

	var queries string
	for source := range uplinkValues {
		uplink := uplinkValues[source]
		downlink := downlinkValues[source]
		sessUplink := sessUplinkValues[source]
		sessDownlink := sessDownlinkValues[source]

		queries += fmt.Sprintf("INSERT OR REPLACE INTO traffic_stats (source, uplink, downlink, sess_uplink, sess_downlink) "+
			"VALUES ('%s', %d, %d, %d, %d) ON CONFLICT(source) DO UPDATE SET uplink = uplink + %d, "+
			"downlink = downlink + %d, sess_uplink = %d, sess_downlink = %d;\n", source, uplink, downlink, sessUplink, sessDownlink, uplink, downlink, sessUplink, sessDownlink)
	}

	if queries != "" {
		_, err := memDB.Exec(queries)
		if err != nil {
			log.Printf("Error executing transaction: %v", err)
		}
	} else {
		log.Printf("Statistics not exist yet")
	}

	previousStats = strings.Join(currentStats, "\n")
}

func updateClientStats(memDB *sql.DB, apiData *api.ApiResponse, cfg *config.Config) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	clientCurrentStats := extractUserTraffic(apiData)

	if clientPreviousStats == "" {
		clientPreviousStats = strings.Join(clientCurrentStats, "\n")
		return
	}

	clientCurrentValues := make(map[string]int)
	clientPreviousValues := make(map[string]int)

	for _, line := range clientCurrentStats {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			clientCurrentValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
		} else {
			log.Printf("Error: invalid line format: %s", line)
		}
	}

	previousLines := strings.Split(clientPreviousStats, "\n")
	for _, line := range previousLines {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			clientPreviousValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
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
		email := parts[0]
		direction := parts[1]

		switch direction {
		case "uplink":
			clientUplinkValues[email] = diff
			clientSessUplinkValues[email] = current
		case "downlink":
			clientDownlinkValues[email] = diff
			clientSessDownlinkValues[email] = current
		}
	}

	for key := range clientPreviousValues {
		parts := strings.Fields(key)
		if len(parts) != 2 {
			continue
		}
		email := parts[0]
		direction := parts[1]

		switch direction {
		case "uplink":
			if _, exists := clientSessUplinkValues[email]; !exists {
				clientSessUplinkValues[email] = 0
				clientUplinkValues[email] = 0
			}
		case "downlink":
			if _, exists := clientSessDownlinkValues[email]; !exists {
				clientSessDownlinkValues[email] = 0
				clientDownlinkValues[email] = 0
			}
		}
	}

	var queries string
	for email := range clientUplinkValues {
		uplink := clientUplinkValues[email]
		downlink := clientDownlinkValues[email]
		sessUplink := clientSessUplinkValues[email]
		sessDownlink := clientSessDownlinkValues[email]

		previousUplink, uplinkExists := clientPreviousValues[email+" uplink"]
		previousDownlink, downlinkExists := clientPreviousValues[email+" downlink"]

		if !uplinkExists {
			previousUplink = 0
		}
		if !downlinkExists {
			previousDownlink = 0
		}

		uplinkOnline := max(sessUplink-previousUplink, 0)
		downlinkOnline := max(sessDownlink-previousDownlink, 0)
		rate := (uplinkOnline + downlinkOnline) * 8 / cfg.MonitorTickerInterval

		// log.Printf("Traffic for email=%s: sessUplink=%d, previousUplink=%d, sessDownlink=%d, previousDownlink=%d, uplinkOnline=%d, downlinkOnline=%d, rate=%d (raw)",
		// 	email, sessUplink, previousUplink, sessDownlink, previousDownlink, uplinkOnline, downlinkOnline, rate)

		queries += fmt.Sprintf("INSERT OR REPLACE INTO clients_stats (email, rate, uplink, downlink, sess_uplink, sess_downlink) "+
			"VALUES ('%s', '%d', %d, %d, %d, %d) ON CONFLICT(email) DO UPDATE SET "+
			"rate = '%d', uplink = uplink + %d, downlink = downlink + %d, "+
			"sess_uplink = %d, sess_downlink = %d;\n",
			email, rate, uplink, downlink, sessUplink, sessDownlink,
			rate, uplink, downlink, sessUplink, sessDownlink)
	}

	if queries != "" {
		_, err := memDB.Exec(queries)
		if err != nil {
			log.Printf("Error executing transaction: %v", err)
		}
	} else {
		log.Printf("Statistics not exist yet")
	}

	clientPreviousStats = strings.Join(clientCurrentStats, "\n")
}

func stringToInt(s string) int {
	result, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("Error converting string '%s' to integer: %v", s, err)
		return 0
	}
	return result
}

type DNSStat struct {
	Email  string
	Domain string
	Count  int
}

func upsertDNSRecordsBatch(tx *sql.Tx, dnsStats map[string]map[string]int) error {
	if !CheckTableExistsTx(tx, "dns_stats") {
		log.Printf("Table dns_stats does not exist in transaction")
		return fmt.Errorf("table dns_stats does not exist")
	}

	for email, domains := range dnsStats {
		for domain, count := range domains {
			_, err := tx.Exec(`
                INSERT INTO dns_stats (email, domain, count) 
                VALUES (?, ?, ?)
                ON CONFLICT(email, domain) 
                DO UPDATE SET count = count + ?`, email, domain, count, count)
			if err != nil {
				return fmt.Errorf("error during batch update of dns_stats: %v", err)
			}
		}
	}
	return nil
}

func CheckTableExistsTx(tx *sql.Tx, tableName string) bool {
	var name string
	err := tx.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Printf("Error checking table existence for %s: %v", tableName, err)
		return false
	}
	return name == tableName
}

func UpdateIPInDB(tx *sql.Tx, email string, ipList []string) error {
	if !CheckTableExistsTx(tx, "clients_stats") {
		log.Printf("Table clients_stats does not exist in transaction, attempting to reinitialize")
		// Здесь мы не можем напрямую вызвать InitDB, так как tx — это транзакция, а не полная база
		// Вместо этого, предполагаем, что вызывающая функция (readNewLines) уже проверила
		return fmt.Errorf("table clients_stats does not exist")
	}

	ipStr := strings.Join(ipList, ",")
	query := `UPDATE clients_stats SET ips = ? WHERE email = ?`
	_, err := tx.Exec(query, ipStr, email)
	if err != nil {
		return fmt.Errorf("error updating data: %v", err)
	}
	return nil
}

func processLogLine(tx *sql.Tx, line string, dnsStats map[string]map[string]int, cfg *config.Config) {
	if !CheckTableExistsTx(tx, "clients_stats") || !CheckTableExistsTx(tx, "dns_stats") {
		log.Printf("Tables clients_stats or dns_stats do not exist in transaction, skipping processLogLine")
		return
	}

	matches := accessLogRegex.FindStringSubmatch(line)
	if len(matches) != 4 {
		return
	}

	email := strings.TrimSpace(matches[3])
	domain := strings.TrimSpace(matches[2])
	ip := matches[1]

	uniqueEntriesMutex.Lock()
	if uniqueEntries[email] == nil {
		uniqueEntries[email] = make(map[string]time.Time)
	}
	uniqueEntries[email][ip] = time.Now()
	uniqueEntriesMutex.Unlock()

	validIPs := []string{}
	for ip, timestamp := range uniqueEntries[email] {
		if time.Since(timestamp) <= cfg.IpTtl {
			validIPs = append(validIPs, ip)
		} else {
			delete(uniqueEntries[email], ip)
		}
	}

	if err := UpdateIPInDB(tx, email, validIPs); err != nil {
		log.Printf("Error updating IP in database: %v", err)
		return
	}

	if dnsStats[email] == nil {
		dnsStats[email] = make(map[string]int)
	}
	dnsStats[email][domain]++
}

func CheckTableExists(db *sql.DB, tableName string) bool {
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Printf("Error checking table existence for %s: %v", tableName, err)
		return false
	}
	return name == tableName
}

func readNewLines(memDB *sql.DB, file *os.File, offset *int64, cfg *config.Config) {
	log.Printf("Starting readNewLines, checking database integrity")
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Проверка существования таблиц
	requiredTables := []string{"clients_stats", "dns_stats"}
	for _, table := range requiredTables {
		if !CheckTableExists(memDB, table) {
			log.Printf("Table %s does not exist, attempting to reinitialize", table)
			if err := db.InitDB(memDB); err != nil {
				log.Printf("Failed to reinitialize database for table %s: %v", table, err)
				return
			}
			log.Printf("Database reinitialized successfully for table %s", table)
		}
	}

	file.Seek(*offset, 0)
	scanner := bufio.NewScanner(file)

	tx, err := memDB.Begin()
	if err != nil {
		log.Printf("Error starting transaction in readNewLines: %v", err)
		return
	}

	dnsStats := make(map[string]map[string]int)

	for scanner.Scan() {
		processLogLine(tx, scanner.Text(), dnsStats, cfg)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file in readNewLines: %v", err)
		tx.Rollback()
		return
	}

	if err := upsertDNSRecordsBatch(tx, dnsStats); err != nil {
		log.Printf("Error during batch update of DNS queries in readNewLines: %v", err)
		tx.Rollback()
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction in readNewLines: %v", err)
		tx.Rollback()
		return
	}

	pos, err := file.Seek(0, 1)
	if err != nil {
		log.Printf("Error retrieving file position in readNewLines: %v", err)
		return
	}
	*offset = pos
}

// Инициализация базы данных
func initFile(cfg *config.Config) (memDB *sql.DB, accessLog, bannedLog *os.File, offset, bannedOffset *int64, err error) {
	_, err = os.Stat(cfg.DatabasePath)
	fileExists := !os.IsNotExist(err)

	memDB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Printf("Error creating in-memory database: %v", err)
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create in-memory database: %v", err)
	}

	if fileExists {
		fileDB, err := sql.Open("sqlite3", cfg.DatabasePath)
		if err != nil {
			log.Printf("Error opening database: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to open database: %v", err)
		}
		defer fileDB.Close()

		if err = db.InitDB(fileDB); err != nil {
			log.Printf("Error initializing database: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to initialize database: %v", err)
		}

		if err = db.BackupDB(fileDB, memDB, cfg); err != nil {
			log.Printf("Error copying data to memory: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to copy data to memory: %v", err)
		}
	} else {
		if err = db.InitDB(memDB); err != nil {
			log.Printf("Error initializing in-memory database: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to initialize in-memory database: %v", err)
		}
	}

	accessLog, err = os.OpenFile(cfg.AccessLogPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Error opening access.log: %v", err)
		memDB.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open access.log: %v", err)
	}

	bannedLog, err = os.OpenFile(cfg.BannedLogFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("Error opening ban log file: %v", err)
		memDB.Close()
		accessLog.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open ban log file: %v", err)
	}

	var accessOffset int64
	accessLog.Seek(0, 2)
	accessOffset, err = accessLog.Seek(0, 1)
	if err != nil {
		log.Printf("Error getting log file position: %v", err)
		memDB.Close()
		accessLog.Close()
		bannedLog.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get log file position: %v", err)
	}

	var banOffset int64
	bannedLog.Seek(0, 2)
	banOffset, err = bannedLog.Seek(0, 1)
	if err != nil {
		log.Printf("Error getting ban log file position: %v", err)
		memDB.Close()
		accessLog.Close()
		bannedLog.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get ban log file position: %v", err)
	}

	return memDB, accessLog, bannedLog, &accessOffset, &banOffset, nil
}

// Запуск задачи мониторинга пользователей и логов
func monitorUsersAndLogs(ctx context.Context, memDB *sql.DB, accessLog *os.File, offset *int64, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Duration(cfg.MonitorTickerInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := db.AddUserToDB(memDB, cfg); err != nil {
					log.Printf("Error adding users: %v", err)
				}
				if err := db.DelUserFromDB(memDB, cfg); err != nil {
					log.Printf("Error deleting users: %v", err)
				}

				apiData, err := api.GetApiResponse(cfg)
				if err != nil {
					log.Printf("Error retrieving API data: %v", err)
				} else {
					updateProxyStats(memDB, apiData)
					updateClientStats(memDB, apiData, cfg)
				}
				readNewLines(memDB, accessLog, offset, cfg)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func startAPIServer(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	server := &http.Server{
		Addr:    "127.0.0.1:" + cfg.Port,
		Handler: nil,
	}

	http.HandleFunc("/api/v1/stats", api.StatsHandler(memDB, &dbMutex, cfg.Services, cfg.Features))

	http.HandleFunc("/api/v1/users", api.UsersHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/add_user", api.AddUserHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/delete_user", api.DeleteUserHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/set_enabled", api.SetEnabledHandler(memDB, cfg))

	http.HandleFunc("/api/v1/dns_stats", api.DnsStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/delete_dns_stats", api.DeleteDNSStatsHandler(memDB, &dbMutex))

	http.HandleFunc("/api/v1/reset_traffic", api.ResetTrafficHandler())
	http.HandleFunc("/api/v1/reset_clients_stats", api.ResetClientsStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/reset_traffic_stats", api.ResetTrafficStatsHandler(memDB, &dbMutex))

	http.HandleFunc("/api/v1/update_lim_ip", api.UpdateIPLimitHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/adjust_date", api.AdjustDateOffsetHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/update_renew", api.UpdateRenewHandler(memDB, &dbMutex))

	go func() {
		// log.Printf("API server starting on 127.0.0.1:%s...", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down server: %v", err)
	}
	// log.Println("API server stopped successfully")

	wg.Done()
}

func main() {
	// Load configuration
	cfg, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Инициализация базы данных и логов
	memDB, accessLog, bannedLog, offset, bannedOffset, err := initFile(&cfg)
	if err != nil {
		log.Fatalf("Failed to initialize file: %v", err)
	}
	defer memDB.Close()
	defer accessLog.Close()
	defer bannedLog.Close()

	log.Printf("Starting v2ray-stat application %s, with core: %s", constant.Version, cfg.CoreType)

	// Setup context and signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start tasks
	wg.Add(1)
	go startAPIServer(ctx, memDB, &cfg, &wg)

	monitorUsersAndLogs(ctx, memDB, accessLog, offset, &cfg, &wg)
	db.MonitorSubscriptionsAndSync(ctx, memDB, &cfg, &wg)
	monitor.MonitorExcessIPs(ctx, memDB, &cfg, &wg)
	monitor.MonitorBannedLogRoutine(ctx, bannedLog, bannedOffset, &cfg, &wg)

	if cfg.Features["network"] {
		if err := stats.InitNetworkMonitoring(); err != nil {
			log.Printf("Failed to initialize network monitoring: %v", err)
		}
		stats.MonitorNetwork(ctx, &cfg, &wg)
	}

	if cfg.Features["report"] {
		stats.MonitorDailyReport(ctx, memDB, &cfg, &wg)
		stats.MonitorStats(ctx, &cfg, &wg)
	}

	// Wait for termination signal
	<-sigChan
	log.Println("Received termination signal, saving data")
	cancel()

	// Synchronize database
	start := time.Now()
	if err := db.SyncToFileDB(memDB, &cfg); err != nil {
		log.Printf("Error synchronizing database: %v [%v]", err, time.Since(start))
	} else {
		log.Printf("Database synchronized successfully [%v]", time.Since(start))
	}

	wg.Wait()
	log.Println("Program completed")
}

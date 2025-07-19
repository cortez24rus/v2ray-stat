package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/manager"
	"v2ray-stat/telegram"
)

var (
	notifiedMutex      sync.Mutex
	notifiedUsers      = make(map[string]bool)
	renewNotifiedUsers = make(map[string]bool)
)

var (
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
)

func extractUsersXrayServer(cfg *config.Config) []config.XrayClient {
	clientMap := make(map[string]config.XrayClient)
	extractClients := func(inbounds []config.XrayInbound) {
		for _, inbound := range inbounds {
			for _, client := range inbound.Settings.Clients {
				clientMap[client.Email] = client
			}
		}
	}

	data, err := os.ReadFile(cfg.Core.Config)
	if err != nil {
		log.Printf("Ошибка чтения config.json: %v", err)
	} else {
		var cfgXray config.ConfigXray
		if err := json.Unmarshal(data, &cfgXray); err != nil {
			log.Printf("Ошибка разбора JSON из config.json: %v", err)
		} else {
			extractClients(cfgXray.Inbounds)
		}
	}

	disabledUsersPath := filepath.Join(cfg.Core.Dir, ".disabled_users")
	disabledData, err := os.ReadFile(disabledUsersPath)
	if err == nil {
		if len(disabledData) != 0 {
			var disabledCfg config.DisabledUsersConfigXray
			if err := json.Unmarshal(disabledData, &disabledCfg); err != nil {
				log.Printf("Ошибка разбора JSON из .disabled_users: %v", err)
			} else {
				extractClients(disabledCfg.Inbounds)
			}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("Ошибка чтения .disabled_users: %v", err)
	}

	var clients []config.XrayClient
	for _, client := range clientMap {
		clients = append(clients, client)
	}
	return clients
}

func extractUsersSingboxServer(cfg *config.Config) []config.XrayClient {
	data, err := os.ReadFile(cfg.Core.Config)
	if err != nil {
		log.Printf("Ошибка чтения config.json для Singbox: %v", err)
		return nil
	}

	var cfgSingbox config.ConfigSingbox
	if err := json.Unmarshal(data, &cfgSingbox); err != nil {
		log.Printf("Ошибка разбора JSON для Singbox: %v", err)
		return nil
	}

	var clients []config.XrayClient
	for _, inbound := range cfgSingbox.Inbounds {
		if inbound.Tag == "vless-in" || inbound.Tag == "trojan-in" {
			for _, user := range inbound.Users {
				client := config.XrayClient{
					Email: user.Name,
				}
				switch inbound.Type {
				case "vless":
					client.ID = user.UUID
				case "trojan":
					client.ID = user.Password
					client.Password = user.UUID
				}
				clients = append(clients, client)
			}
		}
	}
	return clients
}

func AddUserToDB(manager *manager.DatabaseManager, cfg *config.Config) error {
	start := time.Now()
	var clients []config.XrayClient
	switch cfg.V2rayStat.Type {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

	if len(clients) == 0 {
		log.Printf("Не найдены пользователи для добавления в базу данных для типа %s [%v]", cfg.V2rayStat.Type, time.Since(start))
		return nil
	}

	var addedUsers []string
	currentTime := time.Now().Format("2006-01-02-15")

	err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare("INSERT OR IGNORE INTO clients_stats(user, uuid, rate, enabled, created) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			return fmt.Errorf("ошибка подготовки запроса: %v", err)
		}
		defer stmt.Close()

		for _, client := range clients {
			result, err := stmt.Exec(client.Email, client.ID, "0", "true", currentTime)
			if err != nil {
				return fmt.Errorf("ошибка вставки клиента %s: %v", client.Email, err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("ошибка получения RowsAffected для клиента %s: %v", client.Email, err)
			}
			if rowsAffected > 0 {
				addedUsers = append(addedUsers, client.Email)
			}
		}

		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in AddUserToDB: %v [%v]", err, time.Since(start))
		return err
	}

	if len(addedUsers) > 0 {
		log.Printf("Пользователи успешно добавлены в базу данных: %s [%v]", strings.Join(addedUsers, ", "), time.Since(start))
	}
	return nil
}

func DelUserFromDB(manager *manager.DatabaseManager, cfg *config.Config) error {
	start := time.Now()
	var clients []config.XrayClient
	switch cfg.V2rayStat.Type {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

	var usersDB []string
	err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		rows, err := tx.Query("SELECT user FROM clients_stats")
		if err != nil {
			return fmt.Errorf("ошибка выполнения запроса: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var user string
			if err := rows.Scan(&user); err != nil {
				return fmt.Errorf("ошибка сканирования строки: %v", err)
			}
			usersDB = append(usersDB, user)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("ошибка итерации строк: %v", err)
		}
		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in DelUserFromDB (reading users): %v [%v]", err, time.Since(start))
		return err
	}

	var deletedUsers []string
	for _, user := range usersDB {
		found := false
		for _, xrayUser := range clients {
			if user == xrayUser.Email {
				found = true
				break
			}
		}
		if !found {
			deletedUsers = append(deletedUsers, user)
		}
	}

	if len(deletedUsers) > 0 {
		err = manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("ошибка начала транзакции: %v", err)
			}
			defer tx.Rollback()

			stmt, err := tx.Prepare("DELETE FROM clients_stats WHERE user = ?")
			if err != nil {
				return fmt.Errorf("ошибка подготовки запроса: %v", err)
			}
			defer stmt.Close()

			for _, user := range deletedUsers {
				_, err := stmt.Exec(user)
				if err != nil {
					return fmt.Errorf("ошибка удаления пользователя %s: %v", user, err)
				}
			}

			return tx.Commit()
		})
		if err != nil {
			log.Printf("Error in DelUserFromDB (deleting users): %v [%v]", err, time.Since(start))
			return err
		}
		log.Printf("Пользователи успешно удалены из базы данных: %s [%v]", strings.Join(deletedUsers, ", "), time.Since(start))
	}
	return nil
}

func UpdateIPInDB(manager *manager.DatabaseManager, user string, ipList []string) error {
	start := time.Now()
	ipStr := strings.Join(ipList, ",")

	err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		_, err = tx.Exec("UPDATE clients_stats SET ips = ? WHERE user = ?", ipStr, user)
		if err != nil {
			return fmt.Errorf("ошибка обновления IPs для пользователя %s: %v", user, err)
		}

		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in UpdateIPInDB for user %s: %v [%v]", user, err, time.Since(start))
		return err
	}

	return nil
}

func UpsertDNSRecordsBatch(manager *manager.DatabaseManager, dnsStats map[string]map[string]int) error {
	return manager.Execute(func(db *sql.DB) error { // Низкий приоритет
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		for user, domains := range dnsStats {
			for domain, count := range domains {
				_, err := tx.Exec(`
					INSERT INTO dns_stats (user, domain, count)
					VALUES (?, ?, ?)
					ON CONFLICT(user, domain)
					DO UPDATE SET count = count + ?`,
					user, domain, count, count)
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("ошибка выполнения запроса для %s/%s: %v", user, domain, err)
				}
			}
		}
		return tx.Commit()
	})
}

func UpdateEnabledInDB(manager *manager.DatabaseManager, user string, enabled bool) error {
	start := time.Now()
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}

	err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		_, err = tx.Exec("UPDATE clients_stats SET enabled = ? WHERE user = ?", enabledStr, user)
		if err != nil {
			return fmt.Errorf("ошибка обновления статуса enabled для пользователя %s: %v", user, err)
		}

		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in UpdateEnabledInDB for user %s: %v [%v]", user, err, time.Since(start))
		return err
	}

	log.Printf("Enabled status updated for user %s to %s [%v]", user, enabledStr, time.Since(start))
	return nil
}

func formatDate(subEnd string) string {
	t, err := time.ParseInLocation("2006-01-02-15", subEnd, time.Local)
	if err != nil {
		log.Printf("Ошибка парсинга даты %s: %v", subEnd, err)
		return subEnd
	}

	_, offsetSeconds := t.Zone()
	offsetHours := offsetSeconds / 3600

	return fmt.Sprintf("%s UTC%+d", t.Format("2006.01.02 15:04"), offsetHours)
}

func parseAndAdjustDate(offset string, baseDate time.Time) (time.Time, error) {
	matches := dateOffsetRegex.FindStringSubmatch(offset)
	if matches == nil {
		return time.Time{}, fmt.Errorf("неверный формат: %s", offset)
	}

	sign := matches[1]
	daysStr := matches[2]
	hoursStr := matches[3]

	days, _ := strconv.Atoi(daysStr)
	hours := 0
	if hoursStr != "" {
		hours, _ = strconv.Atoi(hoursStr)
	}

	if sign == "-" {
		days = -days
		hours = -hours
	}

	newDate := baseDate.AddDate(0, 0, days).Add(time.Duration(hours) * time.Hour)
	return newDate, nil
}

func AdjustDateOffset(manager *manager.DatabaseManager, user, offset string, baseDate time.Time) error {
	start := time.Now()
	offset = strings.TrimSpace(offset)

	if offset == "0" {
		err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("ошибка начала транзакции: %v", err)
			}
			defer tx.Rollback()

			result, err := tx.Exec("UPDATE clients_stats SET sub_end = '' WHERE user = ?", user)
			if err != nil {
				return fmt.Errorf("ошибка обновления базы данных: %v", err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("ошибка проверки затронутых строк: %v", err)
			}
			if rowsAffected == 0 {
				return fmt.Errorf("пользователь %s не найден", user)
			}

			return tx.Commit()
		})
		if err != nil {
			log.Printf("Error in AdjustDateOffset (resetting subscription): %v [%v]", err, time.Since(start))
			return err
		}
		log.Printf("Установлено неограниченное время для пользователя %s [%v]", user, time.Since(start))
		return nil
	}

	newDate, err := parseAndAdjustDate(offset, baseDate)
	if err != nil {
		log.Printf("Error in AdjustDateOffset (parsing date): %v [%v]", err, time.Since(start))
		return fmt.Errorf("неверный формат смещения: %v", err)
	}

	err = manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		result, err := tx.Exec("UPDATE clients_stats SET sub_end = ? WHERE user = ?", newDate.Format("2006-01-02-15"), user)
		if err != nil {
			return fmt.Errorf("ошибка обновления базы данных: %v", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("ошибка проверки затронутых строк: %v", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("пользователь %s не найден", user)
		}

		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in AdjustDateOffset (updating subscription): %v [%v]", err, time.Since(start))
		return err
	}

	log.Printf("Дата подписки для %s обновлена: %s -> %s (смещение: %s) [%v]", user, baseDate.Format("2006-01-02-15"), newDate.Format("2006-01-02-15"), offset, time.Since(start))
	return nil
}

func CheckExpiredSubscriptions(manager *manager.DatabaseManager, cfg *config.Config) error {
	start := time.Now()

	var subscriptions []struct {
		User    string
		SubEnd  string
		UUID    string
		Enabled string
		Renew   int
	}
	err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		rows, err := tx.Query("SELECT user, sub_end, uuid, enabled, renew FROM clients_stats WHERE sub_end IS NOT NULL")
		if err != nil {
			return fmt.Errorf("ошибка выполнения запроса: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var s struct {
				User    string
				SubEnd  string
				UUID    string
				Enabled string
				Renew   int
			}
			if err := rows.Scan(&s.User, &s.SubEnd, &s.UUID, &s.Enabled, &s.Renew); err != nil {
				log.Printf("Ошибка сканирования строки: %v [%v]", err, time.Since(start))
				continue
			}
			subscriptions = append(subscriptions, s)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("ошибка итерации строк: %v", err)
		}
		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in CheckExpiredSubscriptions (reading subscriptions): %v [%v]", err, time.Since(start))
		return err
	}

	for _, s := range subscriptions {
		if s.SubEnd != "" {
			subEnd, err := time.Parse("2006-01-02-15", s.SubEnd)
			if err != nil {
				log.Printf("Ошибка парсинга даты для %s: %v [%v]", s.User, err, time.Since(start))
				continue
			}

			if subEnd.Before(start) {
				canSendNotifications := cfg.Telegram.BotToken != "" && cfg.Telegram.ChatID != ""

				notifiedMutex.Lock()
				if canSendNotifications && !notifiedUsers[s.User] {
					formattedDate := formatDate(s.SubEnd)
					message := fmt.Sprintf("❌ Подписка истекла\n\n"+
						"Клиент:   *%s*\n"+
						"Дата окончания:   *%s*", s.User, formattedDate)
					if err := telegram.SendNotification(cfg.Telegram.BotToken, cfg.Telegram.ChatID, message); err == nil {
						notifiedUsers[s.User] = true
					} else {
						log.Printf("Ошибка отправки уведомления для %s: %v [%v]", s.User, err, time.Since(start))
					}
				}
				notifiedMutex.Unlock()

				if s.Renew >= 1 {
					offset := fmt.Sprintf("%d", s.Renew)
					err = AdjustDateOffset(manager, s.User, offset, start)
					if err != nil {
						log.Printf("Ошибка продления подписки для %s: %v [%v]", s.User, err, time.Since(start))
						continue
					}
					log.Printf("Автоматически продлена подписка для пользователя %s на %d дней [%v]", s.User, s.Renew, time.Since(start))

					if canSendNotifications {
						notifiedMutex.Lock()
						message := fmt.Sprintf("✅ Подписка продлена\n\n"+
							"Клиент:   *%s*\n"+
							"Продлена на:   *%d дней*", s.User, s.Renew)
						if err := telegram.SendNotification(cfg.Telegram.BotToken, cfg.Telegram.ChatID, message); err == nil {
							renewNotifiedUsers[s.User] = true
						} else {
							log.Printf("Ошибка отправки уведомления о продлении для %s: %v [%v]", s.User, err, time.Since(start))
						}
						notifiedMutex.Unlock()
					}

					notifiedMutex.Lock()
					notifiedUsers[s.User] = false
					renewNotifiedUsers[s.User] = false
					notifiedMutex.Unlock()

					if s.Enabled == "false" {
						err = ToggleUserEnabled(s.User, true, cfg, manager)
						if err != nil {
							log.Printf("Ошибка включения пользователя %s: %v [%v]", s.User, err, time.Since(start))
							continue
						}
						err = UpdateEnabledInDB(manager, s.User, true)
						if err != nil {
							log.Printf("Ошибка обновления статуса enabled для %s: %v [%v]", s.User, err, time.Since(start))
							continue
						}
						log.Printf("Пользователь %s включен [%v]", s.User, time.Since(start))
					}
				} else if s.Enabled == "true" {
					err = ToggleUserEnabled(s.User, false, cfg, manager)
					if err != nil {
						log.Printf("Ошибка отключения пользователя %s: %v [%v]", s.User, err, time.Since(start))
					} else {
						log.Printf("Пользователь %s отключен [%v]", s.User, time.Since(start))
					}
					err = UpdateEnabledInDB(manager, s.User, false)
					if err != nil {
						log.Printf("Ошибка обновления статуса enabled для %s: %v [%v]", s.User, err, time.Since(start))
					}
				}
			} else {
				if s.Enabled == "false" {
					err = ToggleUserEnabled(s.User, true, cfg, manager)
					if err != nil {
						log.Printf("Ошибка включения пользователя %s: %v [%v]", s.User, err, time.Since(start))
						continue
					}
					err = UpdateEnabledInDB(manager, s.User, true)
					if err != nil {
						log.Printf("Ошибка обновления статуса enabled для %s: %v [%v]", s.User, err, time.Since(start))
						continue
					}
					log.Printf("✅ Подписка возобновлена, пользователь %s включен (%s) [%v]", s.User, s.SubEnd, time.Since(start))
				}
			}
		}
	}
	log.Printf("CheckExpiredSubscriptions completed successfully [%v]", time.Since(start))
	return nil
}

func CleanInvalidTrafficTags(manager *manager.DatabaseManager, cfg *config.Config) error {
	start := time.Now()
	var trafficSources []string
	err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		rows, err := tx.Query("SELECT source FROM traffic_stats")
		if err != nil {
			return fmt.Errorf("ошибка получения тегов из traffic_stats: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var source string
			if err := rows.Scan(&source); err != nil {
				return fmt.Errorf("ошибка чтения строки из traffic_stats: %v", err)
			}
			trafficSources = append(trafficSources, source)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("ошибка итерации строк: %v", err)
		}
		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in CleanInvalidTrafficTags (reading sources): %v [%v]", err, time.Since(start))
		return err
	}

	data, err := os.ReadFile(cfg.Core.Config)
	if err != nil {
		log.Printf("Ошибка чтения config.json: %v [%v]", err, time.Since(start))
		return fmt.Errorf("ошибка чтения config.json: %v", err)
	}

	validTags := make(map[string]bool)
	switch cfg.V2rayStat.Type {
	case "xray":
		var cfgXray config.ConfigXray
		if err := json.Unmarshal(data, &cfgXray); err != nil {
			log.Printf("Ошибка разбора JSON для xray: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка разбора JSON для xray: %v", err)
		}
		for _, inbound := range cfgXray.Inbounds {
			validTags[inbound.Tag] = true
		}
		for _, outbound := range cfgXray.Outbounds {
			if tag, ok := outbound["tag"].(string); ok {
				validTags[tag] = true
			}
		}
	case "singbox":
		var cfgSingbox config.ConfigSingbox
		if err := json.Unmarshal(data, &cfgSingbox); err != nil {
			log.Printf("Ошибка разбора JSON для singbox: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка разбора JSON для singbox: %v", err)
		}
		for _, inbound := range cfgSingbox.Inbounds {
			validTags[inbound.Tag] = true
		}
		for _, outbound := range cfgSingbox.Outbounds {
			if tag, ok := outbound["tag"].(string); ok {
				validTags[tag] = true
			}
		}
	}

	var invalidTags []string
	for _, source := range trafficSources {
		if !validTags[source] {
			invalidTags = append(invalidTags, source)
		}
	}

	if len(invalidTags) > 0 {
		err = manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("ошибка начала транзакции: %v", err)
			}
			defer tx.Rollback()

			stmt, err := tx.Prepare("DELETE FROM traffic_stats WHERE source = ?")
			if err != nil {
				return fmt.Errorf("ошибка подготовки запроса: %v", err)
			}
			defer stmt.Close()

			for _, source := range invalidTags {
				_, err := stmt.Exec(source)
				if err != nil {
					return fmt.Errorf("ошибка удаления тега %s: %v", source, err)
				}
			}

			return tx.Commit()
		})
		if err != nil {
			log.Printf("Error in CleanInvalidTrafficTags (deleting tags): %v [%v]", err, time.Since(start))
			return err
		}
		log.Printf("Удалены несуществующие теги из traffic_stats: %s [%v]", strings.Join(invalidTags, ", "), time.Since(start))
	}
	return nil
}

func ToggleUserEnabled(userIdentifier string, enabled bool, cfg *config.Config, manager *manager.DatabaseManager) error {
	start := time.Now()
	mainConfigPath := cfg.Core.Config
	disabledUsersPath := filepath.Join(cfg.Core.Dir, ".disabled_users")

	status := "disabled"
	if enabled {
		status = "enabled"
	}

	switch cfg.V2rayStat.Type {
	case "xray":
		mainConfigData, err := os.ReadFile(mainConfigPath)
		if err != nil {
			log.Printf("Ошибка чтения основного конфига Xray: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка чтения основного конфига Xray: %v", err)
		}
		var mainConfig config.ConfigXray
		if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
			log.Printf("Ошибка разбора основного конфига Xray: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка разбора основного конфига Xray: %v", err)
		}

		var disabledConfig config.DisabledUsersConfigXray
		disabledConfigData, err := os.ReadFile(disabledUsersPath)
		if err != nil {
			if os.IsNotExist(err) {
				disabledConfig = config.DisabledUsersConfigXray{Inbounds: []config.XrayInbound{}}
			} else {
				log.Printf("Ошибка чтения файла отключенных пользователей Xray: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка чтения файла отключенных пользователей Xray: %v", err)
			}
		} else if len(disabledConfigData) == 0 {
			disabledConfig = config.DisabledUsersConfigXray{Inbounds: []config.XrayInbound{}}
		} else {
			if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
				log.Printf("Ошибка разбора файла отключенных пользователей Xray: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка разбора файла отключенных пользователей Xray: %v", err)
			}
		}

		sourceInbounds := mainConfig.Inbounds
		targetInbounds := disabledConfig.Inbounds
		if enabled {
			sourceInbounds = disabledConfig.Inbounds
			targetInbounds = mainConfig.Inbounds
		}

		userMap := make(map[string]config.XrayClient)
		found := false
		for i, inbound := range sourceInbounds {
			if inbound.Protocol == "vless" || inbound.Protocol == "trojan" {
				newClients := make([]config.XrayClient, 0, len(inbound.Settings.Clients))
				clientMap := make(map[string]bool)
				for _, client := range inbound.Settings.Clients {
					if client.Email == userIdentifier {
						if !clientMap[client.Email] {
							userMap[inbound.Tag] = client
							clientMap[client.Email] = true
							found = true
						}
					} else {
						if !clientMap[client.Email] {
							newClients = append(newClients, client)
							clientMap[client.Email] = true
						}
					}
				}
				sourceInbounds[i].Settings.Clients = newClients
			}
		}

		if !found {
			log.Printf("Пользователь %s не найден в inbounds с протоколами vless или trojan [%v]", userIdentifier, time.Since(start))
			return fmt.Errorf("пользователь %s не найден в inbounds с протоколами vless или trojan", userIdentifier)
		}

		for _, inbound := range targetInbounds {
			if inbound.Protocol == "vless" || inbound.Protocol == "trojan" {
				for _, client := range inbound.Settings.Clients {
					if client.Email == userIdentifier {
						log.Printf("Пользователь %s уже существует в целевом конфиге Xray с тегом %s [%v]", userIdentifier, inbound.Tag, time.Since(start))
						return fmt.Errorf("пользователь %s уже существует в целевом конфиге Xray с тегом %s", userIdentifier, inbound.Tag)
					}
				}
			}
		}

		for i, inbound := range targetInbounds {
			if inbound.Protocol == "vless" || inbound.Protocol == "trojan" {
				if client, exists := userMap[inbound.Tag]; exists {
					clientMap := make(map[string]bool)
					newClients := make([]config.XrayClient, 0, len(inbound.Settings.Clients)+1)
					for _, c := range inbound.Settings.Clients {
						if !clientMap[c.Email] {
							newClients = append(newClients, c)
							clientMap[c.Email] = true
						}
					}
					if !clientMap[userIdentifier] {
						newClients = append(newClients, client)
						log.Printf("Пользователь %s %s в inbound с тегом %s для %s [%v]", userIdentifier, status, inbound.Tag, cfg.V2rayStat.Type, time.Since(start))
					}
					targetInbounds[i].Settings.Clients = newClients
				}
			}
		}

		for _, mainInbound := range mainConfig.Inbounds {
			if (mainInbound.Protocol == "vless" || mainInbound.Protocol == "trojan") && !hasInboundXray(targetInbounds, mainInbound.Tag) {
				if client, exists := userMap[mainInbound.Tag]; exists {
					newInbound := mainInbound
					newInbound.Settings.Clients = []config.XrayClient{client}
					targetInbounds = append(targetInbounds, newInbound)
					log.Printf("Создан новый inbound с тегом %s для пользователя %s в Xray [%v]", newInbound.Tag, userIdentifier, time.Since(start))
				}
			}
		}

		if enabled {
			mainConfig.Inbounds = targetInbounds
			disabledConfig.Inbounds = sourceInbounds
		} else {
			mainConfig.Inbounds = sourceInbounds
			disabledConfig.Inbounds = targetInbounds
		}

		mainConfigData, err = json.MarshalIndent(mainConfig, "", "  ")
		if err != nil {
			log.Printf("Ошибка сериализации основного конфига Xray: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка сериализации основного конфига Xray: %v", err)
		}
		if err := os.WriteFile(mainConfigPath, mainConfigData, 0644); err != nil {
			log.Printf("Ошибка записи основного конфига Xray: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка записи основного конфига Xray: %v", err)
		}

		if len(disabledConfig.Inbounds) > 0 {
			disabledConfigData, err = json.MarshalIndent(disabledConfig, "", "  ")
			if err != nil {
				log.Printf("Ошибка сериализации файла отключенных пользователей Xray: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка сериализации файла отключенных пользователей Xray: %v", err)
			}
			if err := os.WriteFile(disabledUsersPath, disabledConfigData, 0644); err != nil {
				log.Printf("Ошибка записи файла отключенных пользователей Xray: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка записи файла отключенных пользователей Xray: %v", err)
			}
		} else {
			if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
				log.Printf("Ошибка удаления пустого файла .disabled_users для Xray: %v [%v]", err, time.Since(start))
			}
		}

	case "singbox":
		mainConfigData, err := os.ReadFile(mainConfigPath)
		if err != nil {
			log.Printf("Ошибка чтения основного конфига Singbox: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка чтения основного конфига Singbox: %v", err)
		}
		var mainConfig config.ConfigSingbox
		if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
			log.Printf("Ошибка разбора основного конфига Singbox: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка разбора основного конфига Singbox: %v", err)
		}

		var disabledConfig config.DisabledUsersConfigSingbox
		disabledConfigData, err := os.ReadFile(disabledUsersPath)
		if err != nil {
			if os.IsNotExist(err) {
				disabledConfig = config.DisabledUsersConfigSingbox{Inbounds: []config.SingboxInbound{}}
			} else {
				log.Printf("Ошибка чтения файла отключенных пользователей Singbox: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка чтения файла отключенных пользователей Singbox: %v", err)
			}
		} else if len(disabledConfigData) == 0 {
			disabledConfig = config.DisabledUsersConfigSingbox{Inbounds: []config.SingboxInbound{}}
		} else {
			if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
				log.Printf("Ошибка разбора файла отключенных пользователей Singbox: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка разбора файла отключенных пользователей Singbox: %v", err)
			}
		}

		sourceInbounds := mainConfig.Inbounds
		targetInbounds := disabledConfig.Inbounds
		if enabled {
			sourceInbounds = disabledConfig.Inbounds
			targetInbounds = mainConfig.Inbounds
		}

		userMap := make(map[string]config.SingboxClient)
		found := false
		for i, inbound := range sourceInbounds {
			if inbound.Type == "vless" || inbound.Type == "trojan" {
				newUsers := make([]config.SingboxClient, 0, len(inbound.Users))
				userNameMap := make(map[string]bool)
				for _, user := range inbound.Users {
					if user.Name == userIdentifier {
						if !userNameMap[user.Name] {
							userMap[inbound.Tag] = user
							userNameMap[user.Name] = true
							found = true
						}
					} else {
						if !userNameMap[user.Name] {
							newUsers = append(newUsers, user)
							userNameMap[user.Name] = true
						}
					}
				}
				sourceInbounds[i].Users = newUsers
			}
		}

		if !found {
			log.Printf("Пользователь %s не найден в inbounds с протоколами vless или trojan для Singbox [%v]", userIdentifier, time.Since(start))
			return fmt.Errorf("пользователь %s не найден в inbounds с протоколами vless или trojan для Singbox", userIdentifier)
		}

		for _, inbound := range targetInbounds {
			if inbound.Type == "vless" || inbound.Type == "trojan" {
				for _, user := range inbound.Users {
					if user.Name == userIdentifier {
						log.Printf("Пользователь %s уже существует в целевом конфиге Singbox с тегом %s [%v]", userIdentifier, inbound.Tag, time.Since(start))
						return fmt.Errorf("пользователь %s уже существует в целевом конфиге Singbox с тегом %s", userIdentifier, inbound.Tag)
					}
				}
			}
		}

		for i, inbound := range targetInbounds {
			if inbound.Type == "vless" || inbound.Type == "trojan" {
				if user, exists := userMap[inbound.Tag]; exists {
					userNameMap := make(map[string]bool)
					newUsers := make([]config.SingboxClient, 0, len(inbound.Users)+1)
					for _, u := range inbound.Users {
						if !userNameMap[u.Name] {
							newUsers = append(newUsers, u)
							userNameMap[u.Name] = true
						}
					}
					if !userNameMap[userIdentifier] {
						newUsers = append(newUsers, user)
						log.Printf("Пользователь %s %s в inbound с тегом %s для %s [%v]", userIdentifier, status, inbound.Tag, cfg.V2rayStat.Type, time.Since(start))
					}
					targetInbounds[i].Users = newUsers
				}
			}
		}

		for _, mainInbound := range mainConfig.Inbounds {
			if (mainInbound.Type == "vless" || mainInbound.Type == "trojan") && !hasInboundSingbox(targetInbounds, mainInbound.Tag) {
				if user, exists := userMap[mainInbound.Tag]; exists {
					newInbound := mainInbound
					newInbound.Users = []config.SingboxClient{user}
					targetInbounds = append(targetInbounds, newInbound)
					log.Printf("Создан новый inbound с тегом %s для пользователя %s в Singbox [%v]", newInbound.Tag, userIdentifier, time.Since(start))
				}
			}
		}

		if enabled {
			mainConfig.Inbounds = targetInbounds
			disabledConfig.Inbounds = sourceInbounds
		} else {
			mainConfig.Inbounds = sourceInbounds
			disabledConfig.Inbounds = targetInbounds
		}

		mainConfigData, err = json.MarshalIndent(mainConfig, "", "  ")
		if err != nil {
			log.Printf("Ошибка сериализации основного конфига Singbox: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка сериализации основного конфига Singbox: %v", err)
		}
		if err := os.WriteFile(mainConfigPath, mainConfigData, 0644); err != nil {
			log.Printf("Ошибка записи основного конфига Singbox: %v [%v]", err, time.Since(start))
			return fmt.Errorf("ошибка записи основного конфига Singbox: %v", err)
		}

		if len(disabledConfig.Inbounds) > 0 {
			disabledConfigData, err = json.MarshalIndent(disabledConfig, "", "  ")
			if err != nil {
				log.Printf("Ошибка сериализации файла отключенных пользователей Singbox: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка сериализации файла отключенных пользователей Singbox: %v", err)
			}
			if err := os.WriteFile(disabledUsersPath, disabledConfigData, 0644); err != nil {
				log.Printf("Ошибка записи файла отключенных пользователей Singbox: %v [%v]", err, time.Since(start))
				return fmt.Errorf("ошибка записи файла отключенных пользователей Singbox: %v", err)
			}
		} else {
			if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
				log.Printf("Ошибка удаления пустого файла .disabled_users для Singbox: %v [%v]", err, time.Since(start))
			}
		}
	}

	return nil
}

func hasInboundXray(inbounds []config.XrayInbound, tag string) bool {
	for _, inbound := range inbounds {
		if inbound.Tag == tag {
			return true
		}
	}
	return false
}

func hasInboundSingbox(inbounds []config.SingboxInbound, tag string) bool {
	for _, inbound := range inbounds {
		if inbound.Tag == tag {
			return true
		}
	}
	return false
}

func LoadIsInactiveFromLastSeen(manager *manager.DatabaseManager) (map[string]bool, error) {
	start := time.Now()
	isInactive := make(map[string]bool)
	err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции: %v", err)
		}
		defer tx.Rollback()

		rows, err := tx.Query("SELECT user, last_seen FROM clients_stats")
		if err != nil {
			return fmt.Errorf("ошибка выполнения запроса: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var user, lastSeen string
			if err := rows.Scan(&user, &lastSeen); err != nil {
				log.Printf("Ошибка сканирования строки для пользователя %s: %v [%v]", user, err, time.Since(start))
				continue
			}
			if lastSeen == "online" {
				isInactive[user] = false
			} else {
				isInactive[user] = true
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("ошибка итерации строк: %v", err)
		}
		return tx.Commit()
	})
	if err != nil {
		log.Printf("Error in LoadIsInactiveFromLastSeen: %v [%v]", err, time.Since(start))
		return nil, err
	}
	return isInactive, nil
}

func InitDB(db *sql.DB, dbType string) error {
	start := time.Now()

	var tableCount int
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='clients_stats'").Scan(&tableCount)
	if err != nil {
		log.Printf("Ошибка проверки существования таблицы для базы %s: %v [%v]", dbType, err, time.Since(start))
		return fmt.Errorf("ошибка проверки существования таблицы для базы %s: %v", dbType, err)
	}
	if tableCount > 0 {
		return nil
	}

	sqlStmt := `
        PRAGMA cache_size = 2000;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA busy_timeout = 5000;

        CREATE TABLE IF NOT EXISTS clients_stats (
            user TEXT PRIMARY KEY,
            uuid TEXT,
            last_seen TEXT DEFAULT '',
            rate INTEGER DEFAULT 0,
            enabled TEXT,
            sub_end TEXT DEFAULT '',
            renew INTEGER DEFAULT 0,
            lim_ip INTEGER DEFAULT 0,
            ips TEXT DEFAULT '',
            uplink INTEGER DEFAULT 0,
            downlink INTEGER DEFAULT 0,
            sess_uplink INTEGER DEFAULT 0,
            sess_downlink INTEGER DEFAULT 0,
            created TEXT
        );

        CREATE TABLE IF NOT EXISTS traffic_stats (
            source TEXT PRIMARY KEY,
            rate INTEGER DEFAULT 0,
            uplink INTEGER DEFAULT 0,
            downlink INTEGER DEFAULT 0,
            sess_uplink INTEGER DEFAULT 0,
            sess_downlink INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS dns_stats (
            user TEXT NOT NULL,
            count INTEGER DEFAULT 1,
            domain TEXT NOT NULL,
            PRIMARY KEY (user, domain)
        );

        CREATE INDEX IF NOT EXISTS idx_clients_stats_user ON clients_stats(user);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_rate ON clients_stats(rate);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_enabled ON clients_stats(enabled);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_sub_end ON clients_stats(sub_end);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_renew ON clients_stats(renew);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_sess_uplink ON clients_stats(sess_uplink);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_sess_downlink ON clients_stats(sess_downlink);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_uplink ON clients_stats(uplink);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_downlink ON clients_stats(downlink);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_lim_ip ON clients_stats(lim_ip);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_ips ON clients_stats(ips);
        CREATE INDEX IF NOT EXISTS idx_clients_stats_last_seen ON clients_stats(last_seen);
    `
	if _, err = db.Exec(sqlStmt); err != nil {
		log.Printf("Ошибка выполнения SQL запроса: %v [%v]", err, time.Since(start))
		return fmt.Errorf("ошибка выполнения SQL запроса: %v", err)
	}

	return nil
}

func InitDatabase(cfg *config.Config) (memDB, fileDB *sql.DB, err error) {
	start := time.Now()
	memDB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Printf("Ошибка создания in-memory базы данных: %v [%v]", err, time.Since(start))
		return nil, nil, fmt.Errorf("не удалось создать in-memory базу данных: %v", err)
	}
	memDB.SetMaxOpenConns(1)
	memDB.SetMaxIdleConns(1)

	if err = InitDB(memDB, "in-memory"); err != nil {
		log.Printf("Ошибка инициализации in-memory базы данных: %v [%v]", err, time.Since(start))
		memDB.Close()
		return nil, nil, fmt.Errorf("не удалось инициализировать in-memory базу данных: %v", err)
	}

	fileDB, err = sql.Open("sqlite3", cfg.Paths.Database)
	if err != nil {
		log.Printf("Ошибка открытия файловой базы данных: %v [%v]", err, time.Since(start))
		memDB.Close()
		return nil, nil, fmt.Errorf("не удалось открыть файловую базу данных: %v", err)
	}
	fileDB.SetMaxOpenConns(1)
	fileDB.SetMaxIdleConns(1)

	fileExists := true
	if _, err := os.Stat(cfg.Paths.Database); os.IsNotExist(err) {
		fileExists = false
	} else if err != nil {
		log.Printf("Ошибка проверки файла базы данных %s: %v [%v]", cfg.Paths.Database, err, time.Since(start))
		memDB.Close()
		fileDB.Close()
		return nil, nil, fmt.Errorf("ошибка проверки файла базы данных: %v", err)
	}

	if fileExists {
		var tableCount int
		err = fileDB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='clients_stats'").Scan(&tableCount)
		if err == nil && tableCount > 0 {
			// Синхронизация file -> memory
			tempManager, err := manager.NewDatabaseManager(fileDB, context.Background(), 1, 50, 100, cfg)
			if err != nil {
				log.Printf("Ошибка создания временного DatabaseManager: %v [%v]", err, time.Since(start))
				memDB.Close()
				fileDB.Close()
				return nil, nil, fmt.Errorf("ошибка создания временного DatabaseManager: %v", err)
			}
			syncCtx, syncCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err = tempManager.SyncDBWithContext(syncCtx, memDB, "file to memory"); err != nil {
				log.Printf("Ошибка синхронизации базы данных (file to memory): %v [%v]", err, time.Since(start))
			}
			syncCancel()
			tempManager.Close()
		}
	}

	if err = InitDB(fileDB, "file"); err != nil {
		log.Printf("Ошибка инициализации файловой базы данных: %v [%v]", err, time.Since(start))
		memDB.Close()
		fileDB.Close()
		return nil, nil, fmt.Errorf("не удалось инициализировать файловую базу данных: %v", err)
	}

	return memDB, fileDB, nil
}

func MonitorSubscriptionsAndSync(ctx context.Context, manager *manager.DatabaseManager, fileDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := CleanInvalidTrafficTags(manager, cfg); err != nil {
					log.Printf("Ошибка очистки несуществующих тегов: %v", err)
				}
				if err := CheckExpiredSubscriptions(manager, cfg); err != nil {
					log.Printf("Ошибка проверки подписок: %v", err)
				}
				syncCtx, syncCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := manager.SyncDBWithContext(syncCtx, fileDB, "memory to file"); err != nil {
					log.Printf("Ошибка периодической синхронизации базы данных: %v", err)
				} else {
					log.Printf("Периодическая синхронизация базы данных (memory to file) выполнена успешно")
				}
				syncCancel()
			case <-ctx.Done():
				return
			}
		}
	}()
}

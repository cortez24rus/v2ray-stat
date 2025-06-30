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
	"v2ray-stat/telegram"

	sqlite3 "github.com/mattn/go-sqlite3"
)

var (
	dbMutex            sync.Mutex
	notifiedMutex      sync.Mutex
	notifiedUsers      = make(map[string]bool)
	renewNotifiedUsers = make(map[string]bool)
)

var (
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
)

func InitDB(db *sql.DB) error {
	start := time.Now()

	_, err := db.Exec(`
		PRAGMA cache_size = 2000;
		PRAGMA journal_mode = MEMORY;
	`)
	if err != nil {
		return fmt.Errorf("error setting PRAGMA: %v", err)
	}

	query := `
		CREATE TABLE IF NOT EXISTS clients_stats (
			email TEXT PRIMARY KEY,
			uuid TEXT,
			rate INTEGER DEFAULT 0,
			enabled TEXT,
			created TEXT,
			sub_end TEXT DEFAULT '',
			renew INTEGER DEFAULT 0,
			lim_ip INTEGER DEFAULT 0,
			ips TEXT DEFAULT '',
			uplink INTEGER DEFAULT 0,
			downlink INTEGER DEFAULT 0,
			sess_uplink INTEGER DEFAULT 0,
			sess_downlink INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS traffic_stats (
			source TEXT PRIMARY KEY,
			uplink INTEGER DEFAULT 0,
			downlink INTEGER DEFAULT 0,
			sess_uplink INTEGER DEFAULT 0,
			sess_downlink INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS dns_stats (
			email TEXT NOT NULL,
			count INTEGER DEFAULT 1,
			domain TEXT NOT NULL,
			PRIMARY KEY (email, domain)
		);
	`

	_, err = db.Exec(query)
	if err != nil {
		return fmt.Errorf("error executing SQL query: %v", err)
	}

	// Создание индексов для таблицы clients_stats
	indexQueries := []string{
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_email ON clients_stats(email);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_rate ON clients_stats(rate);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_enabled ON clients_stats(enabled);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_sub_end ON clients_stats(sub_end);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_renew ON clients_stats(renew);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_sess_uplink ON clients_stats(sess_uplink);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_sess_downlink ON clients_stats(sess_downlink);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_uplink ON clients_stats(uplink);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_downlink ON clients_stats(downlink);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_lim_ip ON clients_stats(lim_ip);",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_ips ON clients_stats(ips);",
	}

	for _, indexQuery := range indexQueries {
		_, err := db.Exec(indexQuery)
		if err != nil {
			return fmt.Errorf("error creating index: %v", err)
		}
	}

	log.Printf("Database initialized successfully [%v]", time.Since(start))
	return nil
}

// BackupDB копирует данные из файловой базы (srcDB) в in-memory базу (memDB) с использованием SQLite Backup API
func BackupDB(srcDB, memDB *sql.DB, cfg *config.Config) error {
	start := time.Now()

	// Получаем соединения к исходной и целевой базам
	srcConn, err := srcDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get connection to source database: %v", err)
	}
	defer srcConn.Close()

	memConn, err := memDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get connection to memory database: %v", err)
	}
	defer memConn.Close()

	// Выполняем резервное копирование через Raw доступ к драйверу
	err = srcConn.Raw(func(srcDriverConn interface{}) error {
		return memConn.Raw(func(memDriverConn interface{}) error {
			// Приводим соединения к типу *sqlite3.SQLiteConn
			srcConnSQLite, ok := srcDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("failed to cast source connection to *sqlite3.SQLiteConn")
			}
			memConnSQLite, ok := memDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("failed to cast memory connection to *sqlite3.SQLiteConn")
			}

			// Инициализируем резервное копирование
			backup, err := memConnSQLite.Backup("main", srcConnSQLite, "main")
			if err != nil {
				return fmt.Errorf("failed to initialize backup: %v", err)
			}
			defer backup.Finish()

			// Копируем все страницы за один шаг
			done, err := backup.Step(-1)
			if err != nil {
				return fmt.Errorf("failed to perform backup: %v", err)
			}
			if !done {
				return fmt.Errorf("backup did not complete")
			}
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("error during backup: %v", err)
	}

	log.Printf("Database backup to memory completed successfully [%v]", time.Since(start))
	return nil
}

func extractUsersXrayServer(cfg *config.Config) []config.XrayClient {
	// Карта для уникальных пользователей по email
	clientMap := make(map[string]config.XrayClient)

	// Функция для извлечения пользователей из inbounds
	extractClients := func(inbounds []config.XrayInbound) {
		for _, inbound := range inbounds {
			for _, client := range inbound.Settings.Clients {
				clientMap[client.Email] = client
			}
		}
	}

	// Чтение и обработка config.json
	data, err := os.ReadFile(cfg.CoreConfig)
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
	} else {
		var cfgXray config.ConfigXray
		if err := json.Unmarshal(data, &cfgXray); err != nil {
			log.Printf("Error parsing JSON from config.json: %v", err)
		} else {
			extractClients(cfgXray.Inbounds)
		}
	}

	// Чтение и обработка .disabled_users
	disabledUsersPath := filepath.Join(cfg.CoreDir, ".disabled_users")
	disabledData, err := os.ReadFile(disabledUsersPath)
	if err == nil {
		// Проверяем, не пустой ли файл
		if len(disabledData) != 0 {
			var disabledCfg config.DisabledUsersConfigXray
			if err := json.Unmarshal(disabledData, &disabledCfg); err != nil {
				log.Printf("Error parsing JSON from .disabled_users: %v", err)
			} else {
				extractClients(disabledCfg.Inbounds)
			}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("Error reading .disabled_users: %v", err)
	}

	// Преобразование карты в список
	var clients []config.XrayClient
	for _, client := range clientMap {
		clients = append(clients, client)
	}

	return clients
}

func extractUsersSingboxServer(cfg *config.Config) []config.XrayClient {
	data, err := os.ReadFile(cfg.CoreConfig)
	if err != nil {
		log.Printf("Error reading config.json for Singbox: %v", err)
		return nil
	}

	var cfgSingbox config.ConfigSingbox
	if err := json.Unmarshal(data, &cfgSingbox); err != nil {
		log.Printf("Error parsing JSON for Singbox: %v", err)
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

func AddUserToDB(memDB *sql.DB, cfg *config.Config) error {
	var clients []config.XrayClient
	switch cfg.CoreType {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

	if len(clients) == 0 {
		log.Printf("No users found to add to the database for type %s", cfg.CoreType)
		return nil
	}

	start := time.Now() // Замер времени начала выполнения

	dbMutex.Lock()
	defer dbMutex.Unlock()

	tx, err := memDB.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO clients_stats(email, uuid, rate, enabled, created) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()

	var addedEmails []string
	currentTime := time.Now().Format("2006-01-02-15")
	for _, client := range clients {
		result, err := stmt.Exec(client.Email, client.ID, "0", "true", currentTime)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error inserting client %s: %v", client.Email, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error getting RowsAffected for client %s: %v", client.Email, err)
		}
		if rowsAffected > 0 {
			addedEmails = append(addedEmails, client.Email)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}

	if len(addedEmails) > 0 {
		log.Printf("Users successfully added to database: %s [%v]", strings.Join(addedEmails, ", "), time.Since(start))
	}

	return nil
}

func DelUserFromDB(memDB *sql.DB, cfg *config.Config) error {
	var clients []config.XrayClient
	switch cfg.CoreType {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

	start := time.Now()

	dbMutex.Lock()
	defer dbMutex.Unlock()

	rows, err := memDB.Query("SELECT email FROM clients_stats")
	if err != nil {
		return fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	var usersDB []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return fmt.Errorf("error scanning row: %v", err)
		}
		usersDB = append(usersDB, email)
	}

	var Queries string
	var deletedEmails []string
	for _, user := range usersDB {
		found := false
		for _, xrayUser := range clients {
			if user == xrayUser.Email {
				found = true
				break
			}
		}
		if !found {
			Queries += fmt.Sprintf("DELETE FROM clients_stats WHERE email = '%s'; ", user)
			deletedEmails = append(deletedEmails, user)
		}
	}

	if Queries != "" {
		_, err := memDB.Exec(Queries)
		if err != nil {
			return fmt.Errorf("error executing transaction: %v", err)
		}
		log.Printf("Users successfully deleted from database: %s [%v]", strings.Join(deletedEmails, ", "), time.Since(start))
	}

	return nil
}

func UpdateIPInDB(tx *sql.Tx, email string, ipList []string) error {
	ipStr := strings.Join(ipList, ",")
	query := `UPDATE clients_stats SET ips = ? WHERE email = ?`
	_, err := tx.Exec(query, ipStr, email)
	if err != nil {
		return fmt.Errorf("error updating data: %v", err)
	}
	return nil
}

func SyncToFileDB(memDB *sql.DB, cfg *config.Config) error {
	// Блокировка мьютекса
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Открытие файловой базы данных
	fileDB, err := sql.Open("sqlite3", cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to open file database at %s: %v", cfg.DatabasePath, err)
	}
	defer fileDB.Close()

	// Проверка и инициализация таблиц
	if !CheckTableExists(fileDB, "clients_stats") {
		if err := InitDB(fileDB); err != nil {
			return fmt.Errorf("ошибка инициализации базы данных: %v", err)
		}
	}

	// Получение соединений
	memConn, err := memDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("ошибка получения соединения с базой в памяти: %v", err)
	}
	defer memConn.Close()

	fileConn, err := fileDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("ошибка получения соединения с файловой базой: %v", err)
	}
	defer fileConn.Close()

	// Резервное копирование через SQLite Backup API
	err = memConn.Raw(func(memDriverConn any) error {
		return fileConn.Raw(func(fileDriverConn any) error {
			// Приводим соединения к типу *sqlite3.SQLiteConn
			memConnSQLite, ok := memDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("не удалось привести соединение с базой в памяти к *sqlite3.SQLiteConn")
			}
			fileConnSQLite, ok := fileDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("не удалось привести соединение с файловой базой к *sqlite3.SQLiteConn")
			}

			// Инициализируем резервное копирование из memDB в fileDB
			backup, err := fileConnSQLite.Backup("main", memConnSQLite, "main")
			if err != nil {
				return fmt.Errorf("ошибка инициализации резервного копирования: %v", err)
			}
			defer backup.Finish()

			// Копируем все страницы за один шаг
			done, err := backup.Step(-1)
			if err != nil {
				return fmt.Errorf("ошибка выполнения резервного копирования: %v", err)
			}
			if !done {
				return fmt.Errorf("резервное копирование не завершено")
			}
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("ошибка во время резервного копирования: %v", err)
	}

	return nil
}

func UpdateEnabledInDB(memDB *sql.DB, email string, enabled bool) {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	_, err := memDB.Exec("UPDATE clients_stats SET enabled = ? WHERE email = ?", enabledStr, email)
	if err != nil {
		log.Printf("Error updating database for email %s: %v", email, err)
	} else {
		// log.Printf("Updated enabled status for %s to %s", email, enabledStr)
	}
}

func formatDate(subEnd string) string {
	t, err := time.ParseInLocation("2006-01-02-15", subEnd, time.Local)
	if err != nil {
		log.Printf("Error parsing date %s: %v", subEnd, err)
		return subEnd
	}

	_, offsetSeconds := t.Zone()
	offsetHours := offsetSeconds / 3600

	return fmt.Sprintf("%s UTC%+d", t.Format("2006.01.02 15:04"), offsetHours)
}

func parseAndAdjustDate(offset string, baseDate time.Time) (time.Time, error) {
	matches := dateOffsetRegex.FindStringSubmatch(offset)
	if matches == nil {
		return time.Time{}, fmt.Errorf("invalid format: %s", offset)
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

func AdjustDateOffset(memDB *sql.DB, email, offset string, baseDate time.Time) error {
	start := time.Now()

	offset = strings.TrimSpace(offset)

	if offset == "0" {
		_, err := memDB.Exec("UPDATE clients_stats SET sub_end = '' WHERE email = ?", email)
		if err != nil {
			return fmt.Errorf("error updating database: %v", err)
		}
		log.Printf("Unlimited time restriction set for email %s", email)
		return nil
	}

	newDate, err := parseAndAdjustDate(offset, baseDate)
	if err != nil {
		return fmt.Errorf("invalid offset format: %v", err)
	}

	_, err = memDB.Exec("UPDATE clients_stats SET sub_end = ? WHERE email = ?", newDate.Format("2006-01-02-15"), email)
	if err != nil {
		return fmt.Errorf("error updating database: %v", err)
	}

	log.Printf("Subscription date for %s updated: %s -> %s (offset: %s) [%v]", email, baseDate.Format("2006-01-02-15"), newDate.Format("2006-01-02-15"), offset, time.Since(start))
	return nil
}

func CheckExpiredSubscriptions(memDB *sql.DB, cfg *config.Config) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	now := time.Now()

	rows, err := memDB.Query("SELECT email, sub_end, uuid, enabled, renew FROM clients_stats WHERE sub_end IS NOT NULL")
	if err != nil {
		log.Printf("Error querying database: %v", err)
		return
	}
	defer rows.Close()

	type subscription struct {
		Email   string
		SubEnd  string
		UUID    string
		Enabled string
		Renew   int
	}
	var subscriptions []subscription

	for rows.Next() {
		var s subscription
		err := rows.Scan(&s.Email, &s.SubEnd, &s.UUID, &s.Enabled, &s.Renew)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		subscriptions = append(subscriptions, s)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Error processing rows: %v", err)
		return
	}

	for _, s := range subscriptions {
		if s.SubEnd != "" {
			subEnd, err := time.Parse("2006-01-02-15", s.SubEnd)
			if err != nil {
				log.Printf("Error parsing date for %s: %v", s.Email, err)
				continue
			}

			if subEnd.Before(now) {
				canSendNotifications := cfg.TelegramBotToken != "" && cfg.TelegramChatId != ""

				notifiedMutex.Lock()
				if canSendNotifications && !notifiedUsers[s.Email] {
					formattedDate := formatDate(s.SubEnd)
					message := fmt.Sprintf("❌ Subscription expired\n\n"+
						"Client:   *%s*\n"+
						"Expiration date:   *%s*", s.Email, formattedDate)
					if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatId, message); err == nil {
						notifiedUsers[s.Email] = true
					}
				}
				notifiedMutex.Unlock()

				if s.Renew >= 1 {
					offset := fmt.Sprintf("%d", s.Renew)
					err = AdjustDateOffset(memDB, s.Email, offset, now)
					if err != nil {
						log.Printf("Error renewing subscription for %s: %v", s.Email, err)
						continue
					}
					log.Printf("Auto-renewed subscription for user %s for %d days", s.Email, s.Renew)

					if canSendNotifications {
						message := fmt.Sprintf("✅ Subscription renewed\n\n"+
							"Client:   *%s*\n"+
							"Renewed for:   *%d days*", s.Email, s.Renew)
						if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatId, message); err == nil {
							renewNotifiedUsers[s.Email] = true
						}
					}

					notifiedMutex.Lock()
					notifiedUsers[s.Email] = false
					renewNotifiedUsers[s.Email] = false
					notifiedMutex.Unlock()

					if s.Enabled == "false" {
						err = ToggleUserEnabled(s.Email, true, cfg, memDB)
						if err != nil {
							log.Printf("Error enabling user %s: %v", s.Email, err)
							continue
						}
						UpdateEnabledInDB(memDB, s.Email, true)
						log.Printf("User %s enabled", s.Email)
					}
				} else if s.Enabled == "true" {
					err = ToggleUserEnabled(s.Email, false, cfg, memDB)
					if err != nil {
						log.Printf("Error disabling user %s: %v", s.Email, err)
					} else {
						log.Printf("User %s disabled", s.Email)
					}
					UpdateEnabledInDB(memDB, s.Email, false)
				}
			} else {
				if s.Enabled == "false" {
					err = ToggleUserEnabled(s.Email, true, cfg, memDB)
					if err != nil {
						log.Printf("Error enabling user %s: %v", s.Email, err)
						continue
					}
					UpdateEnabledInDB(memDB, s.Email, true)
					log.Printf("✅ Subscription resumed, user %s enabled (%s)", s.Email, s.SubEnd)
				}
			}
		}
	}
}

func CleanInvalidTrafficTags(memDB *sql.DB, cfg *config.Config) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Получаем все теги из traffic_stats
	rows, err := memDB.Query("SELECT source FROM traffic_stats")
	if err != nil {
		return fmt.Errorf("error retrieving tags from traffic_stats: %v", err)
	}
	defer rows.Close()

	var trafficSources []string
	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			return fmt.Errorf("error reading row from traffic_stats: %v", err)
		}
		trafficSources = append(trafficSources, source)
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("error processing rows from traffic_stats: %v", err)
	}

	// Извлекаем теги inbounds и outbounds из config.json
	data, err := os.ReadFile(cfg.CoreConfig)
	if err != nil {
		return fmt.Errorf("error reading config.json: %v", err)
	}

	validTags := make(map[string]bool)
	switch cfg.CoreType {
	case "xray":
		var cfgXray config.ConfigXray
		if err := json.Unmarshal(data, &cfgXray); err != nil {
			return fmt.Errorf("error parsing JSON for xray: %v", err)
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
			return fmt.Errorf("error parsing JSON for singbox: %v", err)
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

	// Собираем теги для удаления
	var invalidTags []string
	var queries []string
	for _, source := range trafficSources {
		if !validTags[source] {
			queries = append(queries, fmt.Sprintf("DELETE FROM traffic_stats WHERE source = '%s'", source))
			invalidTags = append(invalidTags, source)
		}
	}

	// Выполняем удаление
	if len(queries) > 0 {
		tx, err := memDB.Begin()
		if err != nil {
			return fmt.Errorf("error starting transaction: %v", err)
		}

		for _, query := range queries {
			if _, err := tx.Exec(query); err != nil {
				tx.Rollback()
				return fmt.Errorf("error executing delete query: %v", err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("error committing transaction: %v", err)
		}

		log.Printf("Deleted non-existent tags from traffic_stats: %s", strings.Join(invalidTags, ", "))
	}

	return nil
}

func ToggleUserEnabled(userIdentifier string, enabled bool, cfg *config.Config, memDB *sql.DB) error {
	start := time.Now()

	mainConfigPath := cfg.CoreConfig
	disabledUsersPath := filepath.Join(cfg.CoreDir, ".disabled_users")

	status := "disabled"
	if enabled {
		status = "enabled"
	}

	switch cfg.CoreType {
	case "xray":
		// Read main config for Xray
		mainConfigData, err := os.ReadFile(mainConfigPath)
		if err != nil {
			return fmt.Errorf("error reading Xray main config: %v", err)
		}
		var mainConfig config.ConfigXray
		if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
			return fmt.Errorf("error parsing Xray main config: %v", err)
		}

		// Read disabled users config for Xray
		var disabledConfig config.DisabledUsersConfigXray
		disabledConfigData, err := os.ReadFile(disabledUsersPath)
		if err != nil {
			if os.IsNotExist(err) {
				disabledConfig = config.DisabledUsersConfigXray{Inbounds: []config.XrayInbound{}}
			} else {
				return fmt.Errorf("error reading Xray disabled users file: %v", err)
			}
		} else if len(disabledConfigData) == 0 {
			disabledConfig = config.DisabledUsersConfigXray{Inbounds: []config.XrayInbound{}}
		} else {
			if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
				return fmt.Errorf("error parsing Xray disabled users file: %v", err)
			}
		}

		// Determine source and target for Xray
		sourceInbounds := mainConfig.Inbounds
		targetInbounds := disabledConfig.Inbounds
		if enabled {
			sourceInbounds = disabledConfig.Inbounds
			targetInbounds = mainConfig.Inbounds
		}

		// Collect users for Xray with deduplication by email and inbound tag
		userMap := make(map[string]config.XrayClient) // Map tag -> client
		found := false
		for i, inbound := range sourceInbounds {
			if inbound.Protocol == "vless" || inbound.Protocol == "trojan" {
				newClients := make([]config.XrayClient, 0, len(inbound.Settings.Clients))
				clientMap := make(map[string]bool) // Track unique emails in inbound
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
			return fmt.Errorf("user %s not found in inbounds with vless or trojan protocols", userIdentifier)
		}

		// Check for duplicates in target inbounds for Xray
		for _, inbound := range targetInbounds {
			if inbound.Protocol == "vless" || inbound.Protocol == "trojan" {
				for _, client := range inbound.Settings.Clients {
					if client.Email == userIdentifier {
						return fmt.Errorf("user %s already exists in target Xray config with tag %s", userIdentifier, inbound.Tag)
					}
				}
			}
		}

		// Add users to existing target inbounds for Xray
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
						log.Printf("User %s set to %s in inbound with tag %s for %s [%v]", userIdentifier, status, inbound.Tag, cfg.CoreType, time.Since(start))
					}
					targetInbounds[i].Settings.Clients = newClients
				}
			}
		}

		// Create new inbounds if they don’t exist in target config for Xray
		for _, mainInbound := range mainConfig.Inbounds {
			if (mainInbound.Protocol == "vless" || mainInbound.Protocol == "trojan") && !hasInboundXray(targetInbounds, mainInbound.Tag) {
				if client, exists := userMap[mainInbound.Tag]; exists {
					newInbound := mainInbound
					newInbound.Settings.Clients = []config.XrayClient{client}
					targetInbounds = append(targetInbounds, newInbound)
					log.Printf("Created new inbound with tag %s for user %s in Xray", newInbound.Tag, userIdentifier)
				}
			}
		}

		// Update configs for Xray
		if enabled {
			mainConfig.Inbounds = targetInbounds
			disabledConfig.Inbounds = sourceInbounds
		} else {
			mainConfig.Inbounds = sourceInbounds
			disabledConfig.Inbounds = targetInbounds
		}

		// Save main config for Xray
		mainConfigData, err = json.MarshalIndent(mainConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("error serializing Xray main config: %v", err)
		}
		if err := os.WriteFile(mainConfigPath, mainConfigData, 0644); err != nil {
			return fmt.Errorf("error writing Xray main config: %v", err)
		}

		// Save disabled users config for Xray
		if len(disabledConfig.Inbounds) > 0 {
			disabledConfigData, err = json.MarshalIndent(disabledConfig, "", "  ")
			if err != nil {
				return fmt.Errorf("error serializing Xray disabled users file: %v", err)
			}
			if err := os.WriteFile(disabledUsersPath, disabledConfigData, 0644); err != nil {
				return fmt.Errorf("error writing Xray disabled users file: %v", err)
			}
		} else {
			if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
				log.Printf("Error removing empty .disabled_users for Xray: %v", err)
			}
		}

	case "singbox":
		// Read main config for Singbox
		mainConfigData, err := os.ReadFile(mainConfigPath)
		if err != nil {
			return fmt.Errorf("error reading Singbox main config: %v", err)
		}
		var mainConfig config.ConfigSingbox
		if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
			return fmt.Errorf("error parsing Singbox main config: %v", err)
		}

		// Read disabled users config for Singbox
		var disabledConfig config.DisabledUsersConfigSingbox
		disabledConfigData, err := os.ReadFile(disabledUsersPath)
		if err != nil {
			if os.IsNotExist(err) {
				disabledConfig = config.DisabledUsersConfigSingbox{Inbounds: []config.SingboxInbound{}}
			} else {
				return fmt.Errorf("error reading Singbox disabled users file: %v", err)
			}
		} else if len(disabledConfigData) == 0 {
			disabledConfig = config.DisabledUsersConfigSingbox{Inbounds: []config.SingboxInbound{}}
		} else {
			if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
				return fmt.Errorf("error parsing Singbox disabled users file: %v", err)
			}
		}

		// Determine source and target for Singbox
		sourceInbounds := mainConfig.Inbounds
		targetInbounds := disabledConfig.Inbounds
		if enabled {
			sourceInbounds = disabledConfig.Inbounds
			targetInbounds = mainConfig.Inbounds
		}

		// Collect users for Singbox with deduplication by name and inbound tag
		userMap := make(map[string]config.SingboxClient) // Map tag -> user
		found := false
		for i, inbound := range sourceInbounds {
			if inbound.Type == "vless" || inbound.Type == "trojan" {
				newUsers := make([]config.SingboxClient, 0, len(inbound.Users))
				userNameMap := make(map[string]bool) // Track unique names in inbound
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
			return fmt.Errorf("user %s not found in inbounds with vless or trojan protocols for Singbox", userIdentifier)
		}

		// Check for duplicates in target inbounds for Singbox
		for _, inbound := range targetInbounds {
			if inbound.Type == "vless" || inbound.Type == "trojan" {
				for _, user := range inbound.Users {
					if user.Name == userIdentifier {
						return fmt.Errorf("user %s already exists in target Singbox config with tag %s", userIdentifier, inbound.Tag)
					}
				}
			}
		}

		// Add users to existing target inbounds for Singbox
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
						log.Printf("User %s set to %s in inbound with tag %s for %s [%v]", userIdentifier, status, inbound.Tag, cfg.CoreType, time.Since(start))
					}
					targetInbounds[i].Users = newUsers
				}
			}
		}

		// Create new inbounds if they don’t exist in target config for Singbox
		for _, mainInbound := range mainConfig.Inbounds {
			if (mainInbound.Type == "vless" || mainInbound.Type == "trojan") && !hasInboundSingbox(targetInbounds, mainInbound.Tag) {
				if user, exists := userMap[mainInbound.Tag]; exists {
					newInbound := mainInbound
					newInbound.Users = []config.SingboxClient{user}
					targetInbounds = append(targetInbounds, newInbound)
					log.Printf("Created new inbound with tag %s for user %s in Singbox", newInbound.Tag, userIdentifier)
				}
			}
		}

		// Update configs for Singbox
		if enabled {
			mainConfig.Inbounds = targetInbounds
			disabledConfig.Inbounds = sourceInbounds
		} else {
			mainConfig.Inbounds = sourceInbounds
			disabledConfig.Inbounds = targetInbounds
		}

		// Save main config for Singbox
		mainConfigData, err = json.MarshalIndent(mainConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("error serializing Singbox main config: %v", err)
		}
		if err := os.WriteFile(mainConfigPath, mainConfigData, 0644); err != nil {
			return fmt.Errorf("error writing Singbox main config: %v", err)
		}

		// Save disabled users config for Singbox
		if len(disabledConfig.Inbounds) > 0 {
			disabledConfigData, err = json.MarshalIndent(disabledConfig, "", "  ")
			if err != nil {
				return fmt.Errorf("error serializing Singbox disabled users file: %v", err)
			}
			if err := os.WriteFile(disabledUsersPath, disabledConfigData, 0644); err != nil {
				return fmt.Errorf("error writing Singbox disabled users file: %v", err)
			}
		} else {
			if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
				log.Printf("Error removing empty .disabled_users for Singbox: %v", err)
			}
		}
	}

	UpdateEnabledInDB(memDB, userIdentifier, enabled)
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

func InitDatabase() (memDB *sql.DB, err error) {
	// Создаём базу данных в оперативной памяти
	memDB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Printf("Ошибка создания in-memory базы данных: %v", err)
		return nil, fmt.Errorf("failed to create in-memory database: %v", err)
	}

	// Инициализируем структуру базы данных
	if err = InitDB(memDB); err != nil {
		log.Printf("Ошибка инициализации in-memory базы данных: %v", err)
		memDB.Close()
		return nil, fmt.Errorf("failed to initialize in-memory database: %v", err)
	}

	return memDB, nil
}

// checkTableExists проверяет, существует ли таблица в базе данных
func CheckTableExists(db *sql.DB, tableName string) bool {
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Printf("Ошибка при проверке существования таблицы %s: %v", tableName, err)
		return false
	}
	return name == tableName
}

// Запуск задачи синхронизации базы и проверки подписок
func MonitorSubscriptionsAndSync(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// if err := CleanInvalidTrafficTags(memDB, cfg); err != nil {
				// 	log.Printf("Error cleaning non-existent tags: %v", err)
				// }
				// CheckExpiredSubscriptions(memDB, cfg)

				start := time.Now()
				if err := SyncToFileDB(memDB, cfg); err != nil {
					log.Printf("Error synchronizing database: %v [%v]", err, time.Since(start))
				} else {
					log.Printf("Database synchronized successfully [%v]", time.Since(start))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func CheckDatabaseIntegrity(db *sql.DB) error {
	start := time.Now()
	tables := []string{"clients_stats", "traffic_stats", "dns_stats"}

	dbMutex.Lock()
	defer dbMutex.Unlock()

	for _, table := range tables {
		if !CheckTableExists(db, table) {
			log.Printf("Ошибка целостности базы данных: таблица %s отсутствует", table)
			return fmt.Errorf("таблица %s отсутствует в базе данных", table)
		}
	}

	log.Printf("Проверка целостности базы данных завершена успешно [%v]", time.Since(start))
	return nil
}

func MonitorDatabaseIntegrity(ctx context.Context, memDB *sql.DB, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := CheckDatabaseIntegrity(memDB); err != nil {
					log.Printf("Ошибка проверки целостности базы данных: %v", err)
				}
			case <-ctx.Done():
				log.Println("Остановка мониторинга целостности базы данных")
				return
			}
		}
	}()
}

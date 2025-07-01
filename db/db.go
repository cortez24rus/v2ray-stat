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
	notifiedMutex      sync.Mutex
	notifiedUsers      = make(map[string]bool)
	renewNotifiedUsers = make(map[string]bool)
)

var (
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
)

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

func AddUserToDB(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) error {
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
	var addedEmails []string
	currentTime := time.Now().Format("2006-01-02-15")

	dbMutex.Lock()
	tx, err := memDB.Begin()
	if err != nil {
		dbMutex.Unlock()
		return fmt.Errorf("error starting transaction: %v", err)
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO clients_stats(email, uuid, rate, enabled, created) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		dbMutex.Unlock()
		return fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()

	for _, client := range clients {
		result, err := stmt.Exec(client.Email, client.ID, "0", "true", currentTime)
		if err != nil {
			tx.Rollback()
			dbMutex.Unlock()
			return fmt.Errorf("error inserting client %s: %v", client.Email, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			dbMutex.Unlock()
			return fmt.Errorf("error getting RowsAffected for client %s: %v", client.Email, err)
		}
		if rowsAffected > 0 {
			addedEmails = append(addedEmails, client.Email)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}
	dbMutex.Unlock()

	if len(addedEmails) > 0 {
		log.Printf("Users successfully added to database: %s [%v]", strings.Join(addedEmails, ", "), time.Since(start))
	}

	return nil
}

func DelUserFromDB(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) error {
	var clients []config.XrayClient
	switch cfg.CoreType {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

	start := time.Now()

	dbMutex.Lock()
	rows, err := memDB.Query("SELECT email FROM clients_stats")
	if err != nil {
		dbMutex.Unlock()
		return fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	var usersDB []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			dbMutex.Unlock()
			return fmt.Errorf("error scanning row: %v", err)
		}
		usersDB = append(usersDB, email)
	}
	dbMutex.Unlock()

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
		dbMutex.Lock()
		_, err := memDB.Exec(Queries)
		dbMutex.Unlock()
		if err != nil {
			return fmt.Errorf("error executing transaction: %v", err)
		}
		log.Printf("Users successfully deleted from database: %s [%v]", strings.Join(deletedEmails, ", "), time.Since(start))
	}

	return nil
}

func UpdateIPInDB(tx *sql.Tx, dbMutex *sync.Mutex, email string, ipList []string) error {
	ipStr := strings.Join(ipList, ",")
	query := `UPDATE clients_stats SET ips = ? WHERE email = ?`
	dbMutex.Lock()
	_, err := tx.Exec(query, ipStr, email)
	dbMutex.Unlock()
	if err != nil {
		return fmt.Errorf("error updating data: %v", err)
	}
	return nil
}

func UpdateEnabledInDB(memDB *sql.DB, dbMutex *sync.Mutex, email string, enabled bool) {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}

	dbMutex.Lock()
	_, err := memDB.Exec("UPDATE clients_stats SET enabled = ? WHERE email = ?", enabledStr, email)
	dbMutex.Unlock()
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

func AdjustDateOffset(memDB *sql.DB, dbMutex *sync.Mutex, email, offset string, baseDate time.Time) error {
	start := time.Now()
	offset = strings.TrimSpace(offset)

	if offset == "0" {
		dbMutex.Lock()
		_, err := memDB.Exec("UPDATE clients_stats SET sub_end = '' WHERE email = ?", email)
		dbMutex.Unlock()
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

	dbMutex.Lock()
	_, err = memDB.Exec("UPDATE clients_stats SET sub_end = ? WHERE email = ?", newDate.Format("2006-01-02-15"), email)
	dbMutex.Unlock()
	if err != nil {
		return fmt.Errorf("error updating database: %v", err)
	}

	log.Printf("Subscription date for %s updated: %s -> %s (offset: %s) [%v]", email, baseDate.Format("2006-01-02-15"), newDate.Format("2006-01-02-15"), offset, time.Since(start))
	return nil
}

func CheckExpiredSubscriptions(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) {
	start := time.Now()

	dbMutex.Lock()
	rows, err := memDB.Query("SELECT email, sub_end, uuid, enabled, renew FROM clients_stats WHERE sub_end IS NOT NULL")
	dbMutex.Unlock()
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

			if subEnd.Before(start) {
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
					err = AdjustDateOffset(memDB, dbMutex, s.Email, offset, start)
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
						err = ToggleUserEnabled(s.Email, true, cfg, memDB, dbMutex)
						if err != nil {
							log.Printf("Error enabling user %s: %v", s.Email, err)
							continue
						}
						UpdateEnabledInDB(memDB, dbMutex, s.Email, true)
						log.Printf("User %s enabled", s.Email)
					}
				} else if s.Enabled == "true" {
					err = ToggleUserEnabled(s.Email, false, cfg, memDB, dbMutex)
					if err != nil {
						log.Printf("Error disabling user %s: %v", s.Email, err)
					} else {
						log.Printf("User %s disabled", s.Email)
					}
					UpdateEnabledInDB(memDB, dbMutex, s.Email, false)
				}
			} else {
				if s.Enabled == "false" {
					err = ToggleUserEnabled(s.Email, true, cfg, memDB, dbMutex)
					if err != nil {
						log.Printf("Error enabling user %s: %v", s.Email, err)
						continue
					}
					UpdateEnabledInDB(memDB, dbMutex, s.Email, true)
					log.Printf("✅ Subscription resumed, user %s enabled (%s)", s.Email, s.SubEnd)
				}
			}
		}
	}
}

func CleanInvalidTrafficTags(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) error {
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
		dbMutex.Lock()
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
		defer dbMutex.Unlock()

		log.Printf("Deleted non-existent tags from traffic_stats: %s", strings.Join(invalidTags, ", "))
	}

	return nil
}

func ToggleUserEnabled(userIdentifier string, enabled bool, cfg *config.Config, memDB *sql.DB, dbMutex *sync.Mutex) error {
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

	UpdateEnabledInDB(memDB, dbMutex, userIdentifier, enabled)
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

// SyncDB копирует данные из исходной базы (srcDB) в целевую базу (destDB) с использованием SQLite Backup API
func SyncDB(srcDB, destDB *sql.DB, dbMutex *sync.Mutex, direction string) error {
	start := time.Now()

	// Получаем соединения к исходной и целевой базам
	srcConn, err := srcDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get connection to source database: %v", err)
	}
	defer srcConn.Close()

	destConn, err := destDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get connection to destination database: %v", err)
	}
	defer destConn.Close()

	dbMutex.Lock()
	defer dbMutex.Unlock()
	// Выполняем резервное копирование через Raw доступ к драйверу
	err = srcConn.Raw(func(srcDriverConn interface{}) error {
		return destConn.Raw(func(destDriverConn interface{}) error {
			// Приводим соединения к типу *sqlite3.SQLiteConn
			srcConnSQLite, ok := srcDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("failed to cast source connection to *sqlite3.SQLiteConn")
			}
			destConnSQLite, ok := destDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("failed to cast destination connection to *sqlite3.SQLiteConn")
			}

			// Инициализируем резервное копирование
			backup, err := destConnSQLite.Backup("main", srcConnSQLite, "main")
			if err != nil {
				return fmt.Errorf("failed to initialize backup: %v", err)
			}
			defer backup.Finish()

			// Копируем 500 страниц за один шаг
			_, err = backup.Step(-1)
			if err != nil {
				return fmt.Errorf("backup step error: %v", err)
			}

			return nil
		})
	})
	if err != nil {
		log.Printf("Error synchronizing database (%s): %v", direction, err)
		return fmt.Errorf("error synchronizing database (%s): %v", direction, err)
	}

	log.Printf("Database synchronized successfully (%s) [%v]", direction, time.Since(start))
	return nil
}

// InitDB инициализирует структуру таблиц в базе данных
func InitDB(db *sql.DB, dbType string) error {
	start := time.Now()

	var tableCount int
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='clients_stats'").Scan(&tableCount)
	if err != nil {
		return fmt.Errorf("error checking table existence for %s database: %v", dbType, err)
	}
	if tableCount > 0 {
		return nil // Таблицы уже существуют, инициализация не требуется
	}

	_, err = db.Exec(`	
		PRAGMA cache_size = 2000;
		PRAGMA journal_mode = MEMORY;
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
	`)
	if err != nil {
		return fmt.Errorf("error executing SQL query: %v", err)
	}

	// Создание индексов для таблицы clients_stats
	indexQueries := []string{
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_email ON clients_stats(email)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_rate ON clients_stats(rate)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_enabled ON clients_stats(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_sub_end ON clients_stats(sub_end)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_renew ON clients_stats(renew)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_sess_uplink ON clients_stats(sess_uplink)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_sess_downlink ON clients_stats(sess_downlink)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_uplink ON clients_stats(uplink)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_downlink ON clients_stats(downlink)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_lim_ip ON clients_stats(lim_ip)",
		"CREATE INDEX IF NOT EXISTS idx_clients_stats_ips ON clients_stats(ips)",
	}

	for _, indexQuery := range indexQueries {
		if _, err := db.Exec(indexQuery); err != nil {
			return fmt.Errorf("error creating index: %v", err)
		}
	}

	log.Printf("%s database initialized successfully [%v]", strings.Title(dbType), time.Since(start))
	return nil
}

// InitDatabase инициализирует in-memory и file базы данных
func InitDatabase(cfg *config.Config, dbMutex *sync.Mutex) (memDB, fileDB *sql.DB, err error) {
	// Создаем in-memory базу
	memDB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Printf("Error creating in-memory database: %v", err)
		return nil, nil, fmt.Errorf("failed to create in-memory database: %v", err)
	}

	// Инициализируем in-memory базу
	if err = InitDB(memDB, "in-memory"); err != nil {
		log.Printf("Error initializing in-memory database: %v", err)
		memDB.Close()
		return nil, nil, fmt.Errorf("failed to initialize in-memory database: %v", err)
	}

	// Открываем или создаем файловую базу
	fileDB, err = sql.Open("sqlite3", cfg.DatabasePath)
	if err != nil {
		log.Printf("Error opening file database: %v", err)
		memDB.Close()
		return nil, nil, fmt.Errorf("failed to open file database: %v", err)
	}

	// Оптимизация файловой базы
	_, err = fileDB.Exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
    `)
	if err != nil {
		log.Printf("Error setting PRAGMA on file database: %v", err)
		memDB.Close()
		fileDB.Close()
		return nil, nil, fmt.Errorf("error setting PRAGMA on file database: %v", err)
	}

	// Проверяем существование файла базы данных
	fileExists := true
	if _, err := os.Stat(cfg.DatabasePath); os.IsNotExist(err) {
		fileExists = false
		log.Printf("File database %s does not exist, will create new file database", cfg.DatabasePath)
	} else if err != nil {
		log.Printf("Error checking file database %s: %v", cfg.DatabasePath, err)
		memDB.Close()
		fileDB.Close()
		return nil, nil, fmt.Errorf("error checking file database: %v", err)
	}

	if fileExists {
		// Проверяем целостность базы
		_, err = fileDB.Exec("SELECT count(*) FROM clients_stats")
		if err != nil {
			fileDB.Close()
			// Удаляем поврежденный файл
			if err := os.Remove(cfg.DatabasePath); err != nil {
				log.Printf("Error removing corrupted database file: %v", err)
				memDB.Close()
				return nil, nil, fmt.Errorf("error removing corrupted database file: %v", err)
			}
			// Создаем новую файловую базу
			fileDB, err = sql.Open("sqlite3", cfg.DatabasePath)
			if err != nil {
				log.Printf("Error creating new file database: %v", err)
				memDB.Close()
				return nil, nil, fmt.Errorf("failed to create new file database: %v", err)
			}
			// Повторно применяем оптимизации
			_, err = fileDB.Exec(`
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA temp_store = MEMORY;
            `)
			if err != nil {
				log.Printf("Error setting PRAGMA on new file database: %v", err)
				memDB.Close()
				fileDB.Close()
				return nil, nil, fmt.Errorf("error setting PRAGMA on new file database: %v", err)
			}
			// Инициализируем новую файловую базу
			if err = InitDB(fileDB, "file"); err != nil {
				log.Printf("Error initializing new file database: %v", err)
				memDB.Close()
				fileDB.Close()
				return nil, nil, fmt.Errorf("failed to initialize new file database: %v", err)
			}
		} else {
			// База цела, инициализируем и синхронизируем данные из файла в память
			if err = InitDB(fileDB, "file"); err != nil {
				log.Printf("Error initializing file database: %v", err)
				memDB.Close()
				fileDB.Close()
				return nil, nil, fmt.Errorf("failed to initialize file database: %v", err)
			}
			// Синхронизируем данные из файла в память
			if err = SyncDB(fileDB, memDB, dbMutex, "file to memory"); err != nil {
				log.Printf("Error synchronizing database (file to memory): %v", err)
			}
		}
	} else {
		// Файла нет, инициализируем новую файловую базу
		if err = InitDB(fileDB, "file"); err != nil {
			log.Printf("Error initializing new file database: %v", err)
			memDB.Close()
			fileDB.Close()
			return nil, nil, fmt.Errorf("failed to initialize new file database: %v", err)
		}
	}

	return memDB, fileDB, nil
}

// Запуск задачи синхронизации базы и проверки подписок
func MonitorSubscriptionsAndSync(ctx context.Context, memDB, fileDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := CleanInvalidTrafficTags(memDB, dbMutex, cfg); err != nil {
					log.Printf("Error cleaning non-existent tags: %v", err)
				}
				CheckExpiredSubscriptions(memDB, dbMutex, cfg)

				if err := SyncDB(memDB, fileDB, dbMutex, "memory to file"); err != nil {
					log.Printf("Error synchronizing database: %v", err)
				}
			case <-ctx.Done():
				if err := SyncDB(memDB, fileDB, dbMutex, "memory to file"); err != nil {
					log.Printf("Error synchronizing database: %v", err)
				}
				return
			}
		}
	}()
}

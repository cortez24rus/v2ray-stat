package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"xcore/config"
	"xcore/stats"
)

type User struct {
	Email   string `json:"email"`
	Enabled string `json:"enabled"`
	Sub_end string `json:"sub_end"`
	Lim_ip  string `json:"lim_ip"`
	Renew   int    `json:"renew"`
}

func UsersHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		rows, err := memDB.Query("SELECT email, enabled, sub_end, renew, lim_ip FROM clients_stats")
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.Email, &user.Enabled, &user.Sub_end, &user.Renew, &user.Lim_ip); err != nil {
				log.Printf("Error reading result: %v", err)
				http.Error(w, "Error processing data", http.StatusInternalServerError)
				return
			}
			users = append(users, user)
		}

		if err := rows.Err(); err != nil {
			log.Printf("Error in query result: %v", err)
			http.Error(w, "Error processing data", http.StatusInternalServerError)
			return
		}

		if err := json.NewEncoder(w).Encode(users); err != nil {
			log.Printf("Error encoding JSON: %v", err)
			http.Error(w, "Error forming response", http.StatusInternalServerError)
			return
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func formatSpeed(speed float64) string {
	if speed >= 1_000_000_000 { // >= 1 Gbit/s (1,000,000,000 bit/s)
		return fmt.Sprintf("%.2f Gbit/s", speed/1_000_000_000)
	} else if speed >= 1_000_000 { // >= 1 Mbit/s (1,000,000 bit/s)
		return fmt.Sprintf("%.2f Mbit/s", speed/1_000_000)
	} else if speed >= 1_000 { // >= 1 kbit/s (1,000 bit/s)
		return fmt.Sprintf("%.2f kbit/s", speed/1_000)
	}
	return fmt.Sprintf("%.0f bit/s", speed) // < 1 kbit/s
}

func StatsHandler(memDB *sql.DB, dbMutex *sync.Mutex, statsEnabled *bool, networkEnabled *bool, trafficMonitor *stats.TrafficMonitor, services []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		formatTable := func(rows *sql.Rows, trafficColumns []string) (string, error) {
			columns, err := rows.Columns()
			if err != nil {
				return "", fmt.Errorf("error retrieving column names: %v", err)
			}

			maxWidths := make([]int, len(columns))
			for i, col := range columns {
				maxWidths[i] = len(col)
			}

			var data [][]string
			for rows.Next() {
				values := make([]interface{}, len(columns))
				valuePtrs := make([]interface{}, len(columns))
				for i := range columns {
					valuePtrs[i] = &values[i]
				}

				if err := rows.Scan(valuePtrs...); err != nil {
					return "", fmt.Errorf("error scanning row: %v", err)
				}

				row := make([]string, len(columns))
				for i, val := range values {
					strVal := fmt.Sprintf("%v", val)
					row[i] = strVal
					if len(strVal) > maxWidths[i] {
						maxWidths[i] = len(strVal)
					}
				}
				data = append(data, row)
			}

			var header strings.Builder
			for i, col := range columns {
				header.WriteString(fmt.Sprintf("%-*s", maxWidths[i]+2, col))
			}
			header.WriteString("\n")

			var separator strings.Builder
			for _, width := range maxWidths {
				separator.WriteString(strings.Repeat("-", width) + "  ")
			}
			separator.WriteString("\n")

			var table strings.Builder
			table.WriteString(header.String())
			table.WriteString(separator.String())
			for _, row := range data {
				for i, val := range row {
					if contains(trafficColumns, columns[i]) {
						table.WriteString(fmt.Sprintf("%*s  ", maxWidths[i], val))
					} else {
						table.WriteString(fmt.Sprintf("%-*s", maxWidths[i]+2, val))
					}
				}
				table.WriteString("\n")
			}

			return table.String(), nil
		}

		var statsBuilder strings.Builder
		if *statsEnabled {
			statsBuilder.WriteString("🖥️  Server State:\n")
			statsBuilder.WriteString(fmt.Sprintf("%-13s %s\n", "Uptime:", stats.GetUptime()))
			statsBuilder.WriteString(fmt.Sprintf("%-13s %s\n", "Load average:", stats.GetLoadAverage()))
			statsBuilder.WriteString(fmt.Sprintf("%-13s %s\n", "Memory:", stats.GetMemoryUsage()))
			statsBuilder.WriteString(fmt.Sprintf("%-13s %s\n", "Disk usage:", stats.GetDiskUsage()))
			statsBuilder.WriteString(fmt.Sprintf("%-13s %s\n", "Status:", stats.GetStatus(services)))
			statsBuilder.WriteString("\n")
		}

		if *networkEnabled {
			rxSpeed, txSpeed, rxPacketsPerSec, txPacketsPerSec, totalRxBytes, totalTxBytes := trafficMonitor.GetStats()
			statsBuilder.WriteString(fmt.Sprintf("📡 Network (%s):\n", trafficMonitor.Iface))
			statsBuilder.WriteString(fmt.Sprintf("   rx: %s   %.0f p/s    %s\n", formatSpeed(rxSpeed), rxPacketsPerSec, stats.FormatTraffic(totalRxBytes)))
			statsBuilder.WriteString(fmt.Sprintf("   tx: %s   %.0f p/s    %s\n\n", formatSpeed(txSpeed), txPacketsPerSec, stats.FormatTraffic(totalTxBytes)))
		}

		statsBuilder.WriteString("🌐 Server Statistics:\n")
		rows, err := memDB.Query(`
            SELECT source AS "Source",
                CASE
                    WHEN sess_uplink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', sess_uplink / 1024.0 / 1024.0 / 1024.0)
                    WHEN sess_uplink >= 1024 * 1024 THEN printf('%.2f MB', sess_uplink / 1024.0 / 1024.0)
                    WHEN sess_uplink >= 1024 THEN printf('%.2f KB', sess_uplink / 1024.0)
                    ELSE printf('%d B', sess_uplink)
                END AS "Sess Up",
                CASE
                    WHEN sess_downlink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', sess_downlink / 1024.0 / 1024.0 / 1024.0)
                    WHEN sess_downlink >= 1024 * 1024 THEN printf('%.2f MB', sess_downlink / 1024.0 / 1024.0)
                    WHEN sess_downlink >= 1024 THEN printf('%.2f KB', sess_downlink / 1024.0)
                    ELSE printf('%d B', sess_downlink)
                END AS "Sess Down",
                CASE
                    WHEN uplink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', uplink / 1024.0 / 1024.0 / 1024.0)
                    WHEN uplink >= 1024 * 1024 THEN printf('%.2f MB', uplink / 1024.0 / 1024.0)
                    WHEN uplink >= 1024 THEN printf('%.2f KB', uplink / 1024.0)
                    ELSE printf('%d B', uplink)
                END AS "Upload",
                CASE
                    WHEN downlink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', downlink / 1024.0 / 1024.0 / 1024.0)
                    WHEN downlink >= 1024 * 1024 THEN printf('%.2f MB', downlink / 1024.0 / 1024.0)
                    WHEN downlink >= 1024 THEN printf('%.2f KB', downlink / 1024.0)
                    ELSE printf('%d B', downlink)
                END AS "Download"
            FROM traffic_stats;
        `)
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		trafficColsServer := []string{"Sess Up", "Sess Down", "Upload", "Download"}
		serverTable, err := formatTable(rows, trafficColsServer)
		if err != nil {
			log.Printf("Error formatting table: %v", err)
			http.Error(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		statsBuilder.WriteString(serverTable)

		statsBuilder.WriteString("\n📊 Client Statistics:\n")
		rows, err = memDB.Query(`
            SELECT email AS "Email",
                status AS "Status",
                enabled AS "Enabled",
                sub_end AS "Sub end",
                renew AS "Renew",
                CASE
                    WHEN sess_uplink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', sess_uplink / 1024.0 / 1024.0 / 1024.0)
                    WHEN sess_uplink >= 1024 * 1024 THEN printf('%.2f MB', sess_uplink / 1024.0 / 1024.0)
                    WHEN sess_uplink >= 1024 THEN printf('%.2f KB', sess_uplink / 1024.0)
                    ELSE printf('%d B', sess_uplink)
                END AS "Sess Up",
                CASE
                    WHEN sess_downlink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', sess_downlink / 1024.0 / 1024.0 / 1024.0)
                    WHEN sess_downlink >= 1024 * 1024 THEN printf('%.2f MB', sess_downlink / 1024.0 / 1024.0)
                    WHEN sess_downlink >= 1024 THEN printf('%.2f KB', sess_downlink / 1024.0)
                    ELSE printf('%d B', sess_downlink)
                END AS "Sess Down",
                CASE
                    WHEN uplink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', uplink / 1024.0 / 1024.0 / 1024.0)
                    WHEN uplink >= 1024 * 1024 THEN printf('%.2f MB', uplink / 1024.0 / 1024.0)
                    WHEN uplink >= 1024 THEN printf('%.2f KB', uplink / 1024.0)
                    ELSE printf('%d B', uplink)
                END AS "Uplink",
                CASE
                    WHEN downlink >= 1024 * 1024 * 1024 THEN printf('%.2f GB', downlink / 1024.0 / 1024.0 / 1024.0)
                    WHEN downlink >= 1024 * 1024 THEN printf('%.2f MB', downlink / 1024.0 / 1024.0)
                    WHEN downlink >= 1024 THEN printf('%.2f KB', downlink / 1024.0)
                    ELSE printf('%d B', downlink)
                END AS "Downlink",
                lim_ip AS "Lim",
                ips AS "Ips"
            FROM clients_stats;
        `)
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		trafficColsClients := []string{"Sess Up", "Sess Down", "Uplink", "Downlink"}
		clientTable, err := formatTable(rows, trafficColsClients)
		if err != nil {
			log.Printf("Error formatting table: %v", err)
			http.Error(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		statsBuilder.WriteString(clientTable)

		fmt.Fprintln(w, statsBuilder.String())
	}
}

func ResetTrafficHandler(trafficMonitor *stats.TrafficMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		if trafficMonitor == nil {
			http.Error(w, "Traffic monitor not initialized", http.StatusInternalServerError)
			return
		}

		err := trafficMonitor.ResetTraffic()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to reset traffic: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Traffic reset successfully")
	}
}

func DnsStatsHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		email := r.URL.Query().Get("email")
		count := r.URL.Query().Get("count")

		if email == "" {
			http.Error(w, "Missing email parameter", http.StatusBadRequest)
			return
		}

		if count == "" {
			count = "20"
		}

		if _, err := strconv.Atoi(count); err != nil {
			http.Error(w, "Invalid count parameter", http.StatusBadRequest)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		stats := " 📊 DNS Query Statistics:\n"
		stats += fmt.Sprintf("%-12s %-6s %-s\n", "Email", "Count", "Domain")
		stats += "-------------------------------------------------------------\n"
		rows, err := memDB.Query(`
			SELECT email AS "Email", count AS "Count", domain AS "Domain"
			FROM dns_stats
			WHERE email = ?
			ORDER BY count DESC
			LIMIT ?`, email, count)
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var email, domain string
			var count int
			if err := rows.Scan(&email, &count, &domain); err != nil {
				log.Printf("Error reading result: %v", err)
				http.Error(w, "Error processing data", http.StatusInternalServerError)
				return
			}
			stats += fmt.Sprintf("%-12s %-6d %-s\n", email, count, domain)
		}

		fmt.Fprintln(w, stats)
	}
}

func UpdateIPLimitHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		ipLimit := r.FormValue("lim_ip")

		if email == "" {
			http.Error(w, "Invalid parameters. Use email", http.StatusBadRequest)
			return
		}

		var ipLimitInt int
		if ipLimit == "" {
			ipLimitInt = 0
		} else {
			var err error
			ipLimitInt, err = strconv.Atoi(ipLimit)
			if err != nil {
				http.Error(w, "lim_ip must be a number", http.StatusBadRequest)
				return
			}

			if ipLimitInt < 0 || ipLimitInt > 100 {
				http.Error(w, "lim_ip must be between 1 and 100", http.StatusBadRequest)
				return
			}
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		query := "UPDATE clients_stats SET lim_ip = ? WHERE email = ?"
		result, err := memDB.Exec(query, ipLimitInt, email)
		if err != nil {
			log.Printf("Error updating lim_ip for email %s: %v", email, err)
			http.Error(w, "Error updating lim_ip", http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Error checking rows affected for email %s: %v", email, err)
			http.Error(w, "Error processing update", http.StatusInternalServerError)
			return
		}

		if rowsAffected == 0 {
			http.Error(w, fmt.Sprintf("User '%s' not found", email), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = fmt.Fprintf(w, "lim_ip for '%s' updated to '%d'\n", email, ipLimitInt)
		if err != nil {
			log.Printf("Error writing response for email %s: %v", email, err)
			http.Error(w, "Error sending response", http.StatusInternalServerError)
			return
		}
	}
}

func DeleteDNSStatsHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		result, err := memDB.Exec("DELETE FROM dns_stats")
		if err != nil {
			log.Printf("Error deleting records from dns_stats: %v", err)
			http.Error(w, "Failed to delete records from dns_stats", http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Error checking rows affected: %v", err)
			http.Error(w, "Error processing deletion", http.StatusInternalServerError)
			return
		}

		log.Printf("Received request to delete dns_stats from %s, %d rows affected", r.RemoteAddr, rowsAffected)
		w.WriteHeader(http.StatusOK)
	}
}

func ResetTrafficStatsHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		result, err := memDB.Exec("UPDATE traffic_stats SET uplink = 0, downlink = 0")
		if err != nil {
			log.Printf("Error resetting traffic statistics: %v", err)
			http.Error(w, "Failed to reset traffic statistics", http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Error retrieving number of affected rows: %v", err)
			http.Error(w, "Error processing result", http.StatusInternalServerError)
			return
		}

		log.Printf("Received request to reset traffic_stats from %s, affected %d rows", r.RemoteAddr, rowsAffected)
		w.WriteHeader(http.StatusOK)
	}
}

func ResetClientsStatsHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		result, err := memDB.Exec("UPDATE clients_stats SET uplink = 0, downlink = 0")
		if err != nil {
			log.Printf("Error resetting traffic statistics: %v", err)
			http.Error(w, "Failed to reset traffic statistics", http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Error retrieving number of affected rows: %v", err)
			http.Error(w, "Error processing result", http.StatusInternalServerError)
			return
		}

		log.Printf("Received request to reset clients_stats from %s, affected %d rows", r.RemoteAddr, rowsAffected)
		w.WriteHeader(http.StatusOK)
	}
}

func UpdateRenewHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "Database not initialized", http.StatusInternalServerError)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing data", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		renewStr := r.FormValue("renew")

		if email == "" {
			http.Error(w, "email is required", http.StatusBadRequest)
			return
		}

		var renew int
		if renewStr == "" {
			renew = 0
		} else {
			var err error
			renew, err = strconv.Atoi(renewStr)
			if err != nil {
				http.Error(w, "renew must be an integer", http.StatusBadRequest)
				return
			}
			if renew < 0 {
				http.Error(w, "renew cannot be negative", http.StatusBadRequest)
				return
			}
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		result, err := memDB.Exec("UPDATE clients_stats SET renew = ? WHERE email = ?", renew, email)
		if err != nil {
			log.Printf("Error updating renew for %s: %v", email, err)
			http.Error(w, "Error updating database", http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Error getting RowsAffected: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		if rowsAffected == 0 {
			http.Error(w, fmt.Sprintf("User '%s' not found", email), http.StatusNotFound)
			return
		}

		log.Printf("Auto-renewal set to %d for user %s", renew, email)
		w.WriteHeader(http.StatusOK)
	}
}

func saveConfig(w http.ResponseWriter, configPath string, configData interface{}, logMessage string) error {
	updateData, err := json.MarshalIndent(configData, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		http.Error(w, "Error updating configuration", http.StatusInternalServerError)
		return err
	}

	if err := os.WriteFile(configPath, updateData, 0644); err != nil {
		log.Printf("Error writing config.json: %v", err)
		http.Error(w, "Error saving configuration", http.StatusInternalServerError)
		return err
	}

	log.Print(logMessage)
	return nil
}

func AddUserHandler(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		uuid := r.FormValue("uuid")
		inboundTag := r.FormValue("inbound")
		if email == "" || uuid == "" {
			http.Error(w, "email and uuid are required", http.StatusBadRequest)
			return
		}
		if inboundTag == "" {
			inboundTag = "vless-in" // Значение по умолчанию
			log.Printf("Параметр inbound не указан, используется значение по умолчанию: %s", inboundTag)
		}

		configPath := cfg.ProxyDir + "config.json"
		data, err := os.ReadFile(configPath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			http.Error(w, "Error reading configuration", http.StatusInternalServerError)
			return
		}

		proxyType := cfg.ProxyType
		var configData interface{}

		switch proxyType {
		case "singbox":
			var cfgSingBox config.ConfigSingBox
			if err := json.Unmarshal(data, &cfgSingBox); err != nil {
				log.Printf("Error parsing JSON: %v", err)
				http.Error(w, "Error parsing configuration", http.StatusInternalServerError)
				return
			}

			found := false
			for i, inbound := range cfgSingBox.Inbounds {
				if inbound.Tag == inboundTag {
					for _, user := range inbound.Users {
						if user.Name == email {
							http.Error(w, `{"error": "User with this email already exists"}`, http.StatusBadRequest)
							return
						}
					}
					cfgSingBox.Inbounds[i].Users = append(cfgSingBox.Inbounds[i].Users, config.SingBoxUser{
						Name: email,
						UUID: uuid,
					})
					found = true
					break
				}
			}
			if !found {
				http.Error(w, `{"error": "Inbound with tag `+inboundTag+` not found"}`, http.StatusNotFound)
				return
			}
			configData = cfgSingBox

		case "xray":
			var cfgXray config.ConfigXray
			if err := json.Unmarshal(data, &cfgXray); err != nil {
				log.Printf("Error parsing JSON: %v", err)
				http.Error(w, "Error parsing configuration", http.StatusInternalServerError)
				return
			}

			found := false
			for i, inbound := range cfgXray.Inbounds {
				if inbound.Tag == inboundTag {
					for _, client := range inbound.Settings.Clients {
						if client.Email == email {
							http.Error(w, `{"error": "User with this email already exists"}`, http.StatusBadRequest)
							return
						}
					}
					cfgXray.Inbounds[i].Settings.Clients = append(cfgXray.Inbounds[i].Settings.Clients, config.Client{
						Email: email,
						ID:    uuid,
					})
					found = true
					break
				}
			}
			if !found {
				http.Error(w, `{"error": "vless-in inbound not found"}`, http.StatusInternalServerError)
				return
			}
			configData = cfgXray
		}

		if err := saveConfig(w, configPath, configData, fmt.Sprintf("User %s with UUID %s added to config.json with inbound %s", email, uuid, inboundTag)); err != nil {
			return
		}
	}
}

func DeleteUserHandler(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodDelete {
			http.Error(w, "Недопустимый метод. Используйте DELETE", http.StatusMethodNotAllowed)
			return
		}

		email := r.FormValue("email")
		inboundTag := r.FormValue("inbound")
		if email == "" {
			log.Printf("Ошибка: параметр email отсутствует или пустой")
			http.Error(w, "Параметр email обязателен", http.StatusBadRequest)
			return
		}
		if inboundTag == "" {
			inboundTag = "vless-in" // Значение по умолчанию
			log.Printf("Параметр inbound не указан, используется значение по умолчанию: %s", inboundTag)
		}

		configPath := cfg.ProxyDir + "config.json"
		data, err := os.ReadFile(configPath)
		if err != nil {
			log.Printf("Ошибка чтения config.json: %v", err)
			http.Error(w, "Не удалось прочитать конфигурацию", http.StatusInternalServerError)
			return
		}

		proxyType := cfg.ProxyType
		var configData interface{}

		switch proxyType {
		case "singbox":
			var cfgSingBox config.ConfigSingBox
			if err := json.Unmarshal(data, &cfgSingBox); err != nil {
				log.Printf("Ошибка разбора JSON: %v", err)
				http.Error(w, "Не удалось разобрать конфигурацию", http.StatusInternalServerError)
				return
			}

			found := false
			for i, inbound := range cfgSingBox.Inbounds {
				if inbound.Tag == inboundTag {
					updatedUsers := make([]config.SingBoxUser, 0, len(inbound.Users))
					for _, user := range inbound.Users {
						if user.Name != email {
							updatedUsers = append(updatedUsers, user)
						} else {
							found = true
						}
					}
					if found {
						cfgSingBox.Inbounds[i].Users = updatedUsers
						break
					}
				}
			}

			if !found {
				http.Error(w, fmt.Sprintf("Пользователь %s не найден в inbound %s", email, inboundTag), http.StatusNotFound)
				return
			}
			configData = cfgSingBox

		case "xray":
			var cfgXray config.ConfigXray
			if err := json.Unmarshal(data, &cfgXray); err != nil {
				log.Printf("Ошибка разбора JSON для Xray: %v", err)
				http.Error(w, "Не удалось разобрать конфигурацию", http.StatusInternalServerError)
				return
			}

			found := false
			for i, inbound := range cfgXray.Inbounds {
				if inbound.Tag == inboundTag {
					updatedClients := make([]config.Client, 0, len(inbound.Settings.Clients))
					for _, client := range inbound.Settings.Clients {
						if client.Email != email {
							updatedClients = append(updatedClients, client)
						} else {
							found = true
						}
					}
					if found {
						cfgXray.Inbounds[i].Settings.Clients = updatedClients
						break
					}
				}
			}

			if !found {
				http.Error(w, fmt.Sprintf("Пользователь %s не найден в inbound %s", email, inboundTag), http.StatusNotFound)
				return
			}
			configData = cfgXray
		}

		if err := saveConfig(w, configPath, configData, fmt.Sprintf("Пользователь %s успешно удалён из config.json, inbound %s", email, inboundTag)); err != nil {
			return
		}
	}
}

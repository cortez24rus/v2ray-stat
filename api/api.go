package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"v2ray-stat/config"
	"v2ray-stat/stats"
)

type User struct {
	Email         string `json:"email"`
	Uuid          string `json:"uuid"`
	Status        string `json:"status"`
	Enabled       string `json:"enabled"`
	Created       string `json:"created"`
	Sub_end       string `json:"sub_end"`
	Renew         int    `json:"renew"`
	Lim_ip        int    `json:"lim_ip"`
	Ips           string `json:"ips"`
	Uplink        int64  `json:"uplink"`
	Downlink      int64  `json:"downlink"`
	Sess_uplink   int64  `json:"sess_uplink"`
	Sess_downlink int64  `json:"sess_downlink"`
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

		rows, err := memDB.Query("SELECT email, uuid, status, enabled, created, sub_end, renew, lim_ip, ips, uplink, downlink, sess_uplink, sess_downlink FROM clients_stats")
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.Email, &user.Uuid, &user.Status, &user.Enabled, &user.Created, &user.Sub_end, &user.Renew, &user.Lim_ip, &user.Ips, &user.Uplink, &user.Downlink, &user.Sess_uplink, &user.Sess_downlink); err != nil {
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

// appendStats is a helper to reduce repetitive WriteString calls
func appendStats(builder *strings.Builder, content string) {
	builder.WriteString(content)
}

// buildServerStateStats collects server state statistics
func buildServerStateStats(builder *strings.Builder, services []string) {
	appendStats(builder, "🖥️  Server State:\n")
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Uptime:", stats.GetUptime()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Load average:", stats.GetLoadAverage()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Memory:", stats.GetMemoryUsage()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Disk usage:", stats.GetDiskUsage()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Status:", stats.GetStatus(services)))
	appendStats(builder, "\n")
}

// buildNetworkStats collects network statistics
func buildNetworkStats(builder *strings.Builder) {
	trafficMonitor := stats.GetTrafficMonitor()
	if trafficMonitor != nil {
		rxSpeed, txSpeed, rxPacketsPerSec, txPacketsPerSec, totalRxBytes, totalTxBytes := trafficMonitor.GetStats()
		appendStats(builder, fmt.Sprintf("📡 Network (%s):\n", trafficMonitor.Iface))
		appendStats(builder, fmt.Sprintf("   rx: %s   %.0f p/s    %s\n", formatSpeed(rxSpeed), rxPacketsPerSec, stats.FormatTraffic(totalRxBytes)))
		appendStats(builder, fmt.Sprintf("   tx: %s   %.0f p/s    %s\n\n", formatSpeed(txSpeed), txPacketsPerSec, stats.FormatTraffic(totalTxBytes)))
	}
}

// buildTrafficStats collects traffic statistics from the database
func buildTrafficStats(builder *strings.Builder, memDB *sql.DB, dbMutex *sync.Mutex) {
	if memDB == nil {
		log.Printf("Database not initialized in buildTrafficStats")
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

	appendStats(builder, "🌐 Server Statistics:\n")
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
		log.Printf("Error executing server stats query: %v", err)
		return
	}
	defer rows.Close()

	trafficColsServer := []string{"Sess Up", "Sess Down", "Upload", "Download"}
	serverTable, _ := formatTable(rows, trafficColsServer)
	appendStats(builder, serverTable)

	appendStats(builder, "\n📊 Client Statistics:\n")
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
		log.Printf("Error executing client stats query: %v", err)
		return
	}
	defer rows.Close()

	trafficColsClients := []string{"Sess Up", "Sess Down", "Uplink", "Downlink"}
	clientTable, _ := formatTable(rows, trafficColsClients)
	appendStats(builder, clientTable)
}

func StatsHandler(memDB *sql.DB, dbMutex *sync.Mutex, services []string, features map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		var statsBuilder strings.Builder

		if features["stats"] {
			buildServerStateStats(&statsBuilder, services)
		}
		if features["network"] {
			buildNetworkStats(&statsBuilder)
		}
		buildTrafficStats(&statsBuilder, memDB, dbMutex)

		fmt.Fprintln(w, statsBuilder.String())
	}
}

func ResetTrafficHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		trafficMonitor := stats.GetTrafficMonitor()
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

		userIdentifier := r.FormValue("user")
		ipLimit := r.FormValue("lim_ip")

		if userIdentifier == "" {
			http.Error(w, "Invalid parameters. Use user", http.StatusBadRequest)
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
		result, err := memDB.Exec(query, ipLimitInt, userIdentifier)
		if err != nil {
			log.Printf("Error updating lim_ip for user %s: %v", userIdentifier, err)
			http.Error(w, "Error updating lim_ip", http.StatusInternalServerError)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Error checking rows affected for user %s: %v", userIdentifier, err)
			http.Error(w, "Error processing update", http.StatusInternalServerError)
			return
		}

		if rowsAffected == 0 {
			http.Error(w, fmt.Sprintf("User '%s' not found", userIdentifier), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = fmt.Fprintf(w, "lim_ip for '%s' updated to '%d'\n", userIdentifier, ipLimitInt)
		if err != nil {
			log.Printf("Error writing response for user %s: %v", userIdentifier, err)
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

		userIdentifier := r.FormValue("user")
		renewStr := r.FormValue("renew")

		if userIdentifier == "" {
			http.Error(w, "user is required", http.StatusBadRequest)
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

		result, err := memDB.Exec("UPDATE clients_stats SET renew = ? WHERE email = ?", renew, userIdentifier)
		if err != nil {
			log.Printf("Error updating renew for %s: %v", userIdentifier, err)
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
			http.Error(w, fmt.Sprintf("User '%s' not found", userIdentifier), http.StatusNotFound)
			return
		}

		log.Printf("Auto-renewal set to %d for user %s", renew, userIdentifier)
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

		userIdentifier := r.FormValue("user")
		credential := r.FormValue("credential")
		inboundTag := r.FormValue("inboundTag")
		if userIdentifier == "" || credential == "" {
			log.Printf("Error: user and credential parameters are missing or empty")
			http.Error(w, "user and credential are required", http.StatusBadRequest)
			return
		}
		if inboundTag == "" {
			inboundTag = "vless-in" // Default value
			log.Printf("inboundTag parameter not specified, using default value: %s", inboundTag)
		}

		configPath := cfg.CoreConfig
		data, err := os.ReadFile(configPath)
		if err != nil {
			log.Printf("Error reading config.json: %v", err)
			http.Error(w, "Error reading configuration", http.StatusInternalServerError)
			return
		}

		proxyType := cfg.CoreType
		var configData interface{}

		switch proxyType {
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
					protocol := inbound.Protocol
					for _, client := range inbound.Settings.Clients {
						if protocol == "vless" && client.ID == credential {
							http.Error(w, `{"error": "User with this id already exists"}`, http.StatusBadRequest)
							return
						} else if protocol == "trojan" && client.Password == credential {
							http.Error(w, `{"error": "User with this password already exists"}`, http.StatusBadRequest)
							return
						}
					}
					newClient := config.XrayClient{Email: userIdentifier}
					switch protocol {
					case "vless":
						newClient.ID = credential
					case "trojan":
						newClient.Password = credential
					}

					cfgXray.Inbounds[i].Settings.Clients = append(cfgXray.Inbounds[i].Settings.Clients, newClient)
					found = true
					break
				}
			}
			if !found {
				http.Error(w, fmt.Sprintf(`{"error": "Inbound with tag %s not found"}`, inboundTag), http.StatusNotFound)
				return
			}
			configData = cfgXray

		case "singbox":
			var cfgSingBox config.ConfigSingbox
			if err := json.Unmarshal(data, &cfgSingBox); err != nil {
				log.Printf("Error parsing JSON: %v", err)
				http.Error(w, "Error parsing configuration", http.StatusInternalServerError)
				return
			}

			found := false
			for i, inbound := range cfgSingBox.Inbounds {
				protocol := inbound.Type
				if inbound.Tag == inboundTag {
					for _, user := range inbound.Users {
						if protocol == "vless" && user.UUID == credential {
							http.Error(w, `{"error": "User with this uuid already exists"}`, http.StatusBadRequest)
							return
						} else if protocol == "trojan" && user.Password == credential {
							http.Error(w, `{"error": "User with this password already exists"}`, http.StatusBadRequest)
							return
						}
					}
					newUser := config.SingboxClient{Name: userIdentifier}
					switch protocol {
					case "vless":
						newUser.UUID = credential
					case "trojan":
						newUser.Password = credential
					}

					cfgSingBox.Inbounds[i].Users = append(cfgSingBox.Inbounds[i].Users, newUser)
					found = true
					break
				}
			}
			if !found {
				http.Error(w, fmt.Sprintf(`{"error": "Inbound with tag %s not found"}`, inboundTag), http.StatusNotFound)
				return
			}
			configData = cfgSingBox
		}

		if err := saveConfig(w, configPath, configData, fmt.Sprintf("User %s with UUID %s added to config.json with inbound %s", userIdentifier, credential, inboundTag)); err != nil {
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func DeleteUserHandler(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodDelete {
			http.Error(w, "Invalid method. Use DELETE", http.StatusMethodNotAllowed)
			return
		}

		userIdentifier := r.FormValue("user") // For Xray this is email, for Singbox this is name
		inboundTag := r.FormValue("inboundTag")
		if userIdentifier == "" {
			log.Printf("Error: user parameter is missing or empty")
			http.Error(w, "user parameter is required", http.StatusBadRequest)
			return
		}
		if inboundTag == "" {
			inboundTag = "vless-in" // Default value
			log.Printf("inboundTag parameter not specified, using default value: %s", inboundTag)
		}

		configPath := cfg.CoreConfig
		disabledUsersPath := filepath.Join(cfg.CoreDir, ".disabled_users")

		proxyType := cfg.CoreType

		switch proxyType {
		case "xray":
			// Read main config
			mainConfigData, err := os.ReadFile(configPath)
			if err != nil {
				log.Printf("Error reading config.json: %v", err)
				http.Error(w, "Failed to read configuration", http.StatusInternalServerError)
				return
			}
			var mainConfig config.ConfigXray
			if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
				log.Printf("Error parsing JSON for config.json: %v", err)
				http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
				return
			}

			// Read disabled users config
			var disabledConfig config.DisabledUsersConfigXray
			disabledConfigData, err := os.ReadFile(disabledUsersPath)
			if err == nil && len(disabledConfigData) > 0 {
				if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
					log.Printf("Error parsing JSON for .disabled_users: %v", err)
					http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
					return
				}
			} else {
				disabledConfig = config.DisabledUsersConfigXray{Inbounds: []config.XrayInbound{}}
			}

			// Function to remove user from inbounds (Xray)
			removeXrayUser := func(inbounds []config.XrayInbound) ([]config.XrayInbound, bool) {
				for i, inbound := range inbounds {
					if inbound.Tag == inboundTag {
						updatedClients := make([]config.XrayClient, 0, len(inbound.Settings.Clients))
						for _, client := range inbound.Settings.Clients {
							if client.Email != userIdentifier {
								updatedClients = append(updatedClients, client)
							}
						}
						if len(updatedClients) < len(inbound.Settings.Clients) {
							inbounds[i].Settings.Clients = updatedClients
							return inbounds, true
						}
					}
				}
				return inbounds, false
			}

			// Check and remove from config.json
			mainUpdated, removedFromMain := removeXrayUser(mainConfig.Inbounds)
			if removedFromMain {
				mainConfig.Inbounds = mainUpdated
				if err := saveConfig(w, configPath, mainConfig, fmt.Sprintf("User %s successfully removed from config.json, inbound %s", userIdentifier, inboundTag)); err != nil {
					return
				}
				return
			}

			// Check and remove from .disabled_users
			disabledUpdated, removedFromDisabled := removeXrayUser(disabledConfig.Inbounds)
			if removedFromDisabled {
				disabledConfig.Inbounds = disabledUpdated
				if len(disabledConfig.Inbounds) > 0 {
					if err := saveConfig(w, disabledUsersPath, disabledConfig, fmt.Sprintf("User %s successfully removed from .disabled_users, inbound %s", userIdentifier, inboundTag)); err != nil {
						return
					}
				} else {
					if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
						log.Printf("Error removing empty .disabled_users: %v", err)
					}
				}
				return
			}

			// If user not found
			http.Error(w, fmt.Sprintf("User %s not found in inbound %s in either config.json or .disabled_users", userIdentifier, inboundTag), http.StatusNotFound)

		case "singbox":
			// Read main config Singbox
			mainConfigData, err := os.ReadFile(configPath)
			if err != nil {
				log.Printf("Error reading config.json: %v", err)
				http.Error(w, "Failed to read configuration", http.StatusInternalServerError)
				return
			}
			var mainConfig config.ConfigSingbox
			if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
				log.Printf("Error parsing JSON for config.json: %v", err)
				http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
				return
			}

			// Read disabled users config Singbox
			var disabledConfig config.DisabledUsersConfigSingbox
			disabledConfigData, err := os.ReadFile(disabledUsersPath)
			if err == nil && len(disabledConfigData) > 0 {
				if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
					log.Printf("Error parsing JSON for .disabled_users: %v", err)
					http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
					return
				}
			} else {
				disabledConfig = config.DisabledUsersConfigSingbox{Inbounds: []config.SingboxInbound{}}
			}

			// Function to remove user from inbounds (Singbox)
			removeSingboxUser := func(inbounds []config.SingboxInbound) ([]config.SingboxInbound, bool) {
				for i, inbound := range inbounds {
					if inbound.Tag == inboundTag {
						updatedUsers := make([]config.SingboxClient, 0, len(inbound.Users))
						for _, user := range inbound.Users {
							if user.Name != userIdentifier {
								updatedUsers = append(updatedUsers, user)
							}
						}
						if len(updatedUsers) < len(inbound.Users) {
							inbounds[i].Users = updatedUsers
							return inbounds, true
						}
					}
				}
				return inbounds, false
			}

			// Check and remove from config.json
			mainUpdated, removedFromMain := removeSingboxUser(mainConfig.Inbounds)
			if removedFromMain {
				mainConfig.Inbounds = mainUpdated
				if err := saveConfig(w, configPath, mainConfig, fmt.Sprintf("User %s successfully removed from config.json, inbound %s", userIdentifier, inboundTag)); err != nil {
					return
				}
				return
			}

			// Check and remove from .disabled_users
			disabledUpdated, removedFromDisabled := removeSingboxUser(disabledConfig.Inbounds)
			if removedFromDisabled {
				disabledConfig.Inbounds = disabledUpdated
				if len(disabledConfig.Inbounds) > 0 {
					if err := saveConfig(w, disabledUsersPath, disabledConfig, fmt.Sprintf("User %s successfully removed from .disabled_users, inbound %s", userIdentifier, inboundTag)); err != nil {
						return
					}
				} else {
					if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
						log.Printf("Error removing empty .disabled_users: %v", err)
					}
				}
				return
			}

			// If user not found
			http.Error(w, fmt.Sprintf("User %s not found in inbound %s in either config.json or .disabled_users", userIdentifier, inboundTag), http.StatusNotFound)
		}
	}
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
		log.Printf("Updated enabled status for %s to %s", email, enabledStr)
	}
}

func SetEnabledHandler(memDB *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		userIdentifier := r.FormValue("user")
		enabledStr := r.FormValue("enabled")

		if userIdentifier == "" {
			http.Error(w, "user is required", http.StatusBadRequest)
			return
		}

		var enabled bool
		if enabledStr == "" {
			enabled = true
			enabledStr = "true"
		} else {
			var err error
			enabled, err = strconv.ParseBool(enabledStr)
			if err != nil {
				http.Error(w, "enabled must be true or false", http.StatusBadRequest)
				return
			}
		}

		if err := ToggleUserEnabled(userIdentifier, enabled, cfg, memDB); err != nil {
			log.Printf("Error changing status: %v", err)
			http.Error(w, "Error updating status", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func ToggleUserEnabled(userIdentifier string, enabled bool, cfg *config.Config, memDB *sql.DB) error {
	mainConfigPath := cfg.CoreConfig
	disabledUsersPath := filepath.Join(cfg.CoreDir, ".disabled_users")

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
						log.Printf("Added user %s to inbound with tag %s for Xray", userIdentifier, inbound.Tag)
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
						log.Printf("Added user %s to inbound with tag %s for Singbox", userIdentifier, inbound.Tag)
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
	log.Printf("User %s successfully moved (enabled=%t) to inbounds", userIdentifier, enabled)
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

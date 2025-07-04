package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/db"
	"v2ray-stat/lua"
	"v2ray-stat/stats"
)

type User struct {
	User          string `json:"user"`
	Uuid          string `json:"uuid"`
	Rate          string `json:"rate"`
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

		rows, err := memDB.Query("SELECT user, uuid, rate, enabled, created, sub_end, renew, lim_ip, ips, uplink, downlink, sess_uplink, sess_downlink FROM clients_stats")
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.User, &user.Uuid, &user.Rate, &user.Enabled, &user.Created, &user.Sub_end, &user.Renew, &user.Lim_ip, &user.Ips, &user.Uplink, &user.Downlink, &user.Sess_uplink, &user.Sess_downlink); err != nil {
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
	return slices.Contains(slice, item)
}

func formatSpeed(speed float64) string {
	const (
		gbit = 1_000_000_000
		mbit = 1_000_000
		kbit = 1_000
	)
	switch {
	case speed >= gbit:
		return fmt.Sprintf("%.2f Gbit/s", speed/1_000_000_000)
	case speed >= mbit:
		return fmt.Sprintf("%.2f Mbit/s", speed/1_000_000)
	case speed >= kbit:
		return fmt.Sprintf("%.2f kbit/s", speed/1_000)
	default:
		return fmt.Sprintf("%.0f bit/s", speed)
	}
}

func formatTraffic(value int64, isRate bool) string {
	if isRate {
		// Для rate (бит/с)
		if value >= 1000*1000*1000 {
			return fmt.Sprintf("%.2f Gbps", float64(value)/1000.0/1000.0/1000.0)
		} else if value >= 1000*1000 {
			return fmt.Sprintf("%.2f Mbps", float64(value)/1000.0/1000.0)
		} else if value >= 1000 {
			return fmt.Sprintf("%.2f Kbps", float64(value)/1000.0)
		}
		return fmt.Sprintf("%d bps", value)
	}
	// Для uplink/downlink (байты)
	if value >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(value)/1024.0/1024.0/1024.0)
	} else if value >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(value)/1024.0/1024.0)
	} else if value >= 1024 {
		return fmt.Sprintf("%.2f KB", float64(value)/1024.0)
	}
	return fmt.Sprintf("%d B", value)
}

// appendStats is a helper to reduce repetitive WriteString calls
func appendStats(builder *strings.Builder, content string) {
	builder.WriteString(content)
}

// buildServerStateStats collects server state statistics
func buildServerStateStats(builder *strings.Builder, services []string) {
	appendStats(builder, "➤  Server State:\n")
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
		appendStats(builder, fmt.Sprintf("➤  Network (%s):\n", trafficMonitor.Iface))
		appendStats(builder, fmt.Sprintf("   rx: %s   %.0f p/s    %s\n", formatSpeed(rxSpeed), rxPacketsPerSec, stats.FormatTraffic(totalRxBytes)))
		appendStats(builder, fmt.Sprintf("   tx: %s   %.0f p/s    %s\n\n", formatSpeed(txSpeed), txPacketsPerSec, stats.FormatTraffic(totalTxBytes)))
	}
}

func buildTrafficStats(builder *strings.Builder, memDB *sql.DB, dbMutex *sync.Mutex, mode, sortBy, sortOrder string) {
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
			values := make([]any, len(columns))
			valuePtrs := make([]any, len(columns))
			for i := range columns {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				return "", fmt.Errorf("error scanning row: %v", err)
			}

			row := make([]string, len(columns))
			for i, val := range values {
				strVal := fmt.Sprintf("%v", val)
				if contains(trafficColumns, columns[i]) {
					if numVal, ok := val.(int64); ok {
						isRate := columns[i] == "Rate"
						strVal = formatTraffic(numVal, isRate)
					}
				}
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

	appendStats(builder, "➤  Server Statistics:\n")
	var serverQuery string
	var trafficColsServer []string
	switch mode {
	case "minimal":
		serverQuery = `
            SELECT source AS "Source", 
				uplink AS "Uplink", 
				downlink AS "Downlink"
            FROM traffic_stats;
        `
		trafficColsServer = []string{"Uplink", "Downlink"}
	case "standard", "extended", "full":
		serverQuery = `
            SELECT source AS "Source", 
				sess_uplink AS "Sess Up", 
				sess_downlink AS "Sess Down",
				uplink AS "Uplink", 
				downlink AS "Downlink"
            FROM traffic_stats;
        `
		trafficColsServer = []string{"Sess Up", "Sess Down", "Uplink", "Downlink"}
	}

	rows, err := memDB.Query(serverQuery)
	if err != nil {
		log.Printf("Error executing server stats query: %v", err)
		return
	}
	defer rows.Close()

	serverTable, _ := formatTable(rows, trafficColsServer)
	appendStats(builder, serverTable)

	appendStats(builder, "\n➤  Client Statistics:\n")
	var clientQuery string
	var trafficColsClients []string
	switch mode {
	case "minimal":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", rate AS "Rate", uplink AS "Uplink", downlink AS "Downlink"
            FROM clients_stats
            ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Uplink", "Downlink"}
	case "standard":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", 
				rate AS "Rate", 
				sess_uplink AS "Sess Up", 
				sess_downlink AS "Sess Down",
                uplink AS "Uplink", 
				downlink AS "Downlink"
            FROM clients_stats
			ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Sess Up", "Sess Down", "Uplink", "Downlink"}
	case "extended":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", 
				rate AS "Rate", 
				enabled AS "Enabled", 
				sub_end AS "Sub end",
                renew AS "Renew", 
				sess_uplink AS "Sess Up", 
				sess_downlink AS "Sess Down",
                uplink AS "Uplink", 
				downlink AS "Downlink", 
				lim_ip AS "Lim", 
				ips AS "Ips"
            FROM clients_stats
			ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Sess Up", "Sess Down", "Uplink", "Downlink"}
	case "full":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", 
				uuid AS "ID",
				rate AS "Rate", 
				enabled AS "Enabled", 
				sub_end AS "Sub end",
                renew AS "Renew", 
				sess_uplink AS "Sess Up", 
				sess_downlink AS "Sess Down",
                uplink AS "Uplink", 
				downlink AS "Downlink", 
				lim_ip AS "Lim", 
				ips AS "Ips"
            FROM clients_stats
			ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Sess Up", "Sess Down", "Uplink", "Downlink"}
	}

	rows, err = memDB.Query(clientQuery)
	if err != nil {
		log.Printf("Error executing client stats query: %v", err)
		return
	}
	defer rows.Close()

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

		// Проверяем параметр mode
		mode := r.URL.Query().Get("mode")
		validModes := []string{"minimal", "standard", "extended", "full"}
		if !contains(validModes, mode) {
			if mode != "" {
				http.Error(w, fmt.Sprintf("Invalid mode parameter: %s, must be one of %v", mode, validModes), http.StatusBadRequest)
				return
			}
			mode = "minimal"
		}

		// Проверяем параметр sort_by
		sortBy := r.URL.Query().Get("sort_by")
		validSortColumns := []string{"user", "uuid", "rate", "enabled", "sub_end", "renew", "sess_uplink", "sess_downlink", "uplink", "downlink", "lim_ip"}
		if !contains(validSortColumns, sortBy) {
			if sortBy != "" {
				http.Error(w, fmt.Sprintf("Invalid sort_by parameter: %s, must be one of %v", sortBy, validSortColumns), http.StatusBadRequest)
				return
			}
			sortBy = "user"
		}

		// Проверяем параметр sort_order
		sortOrder := r.URL.Query().Get("sort_order")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			if sortOrder != "" {
				http.Error(w, fmt.Sprintf("Invalid sort_order parameter: %s, must be ASC or DESC", sortOrder), http.StatusBadRequest)
				return
			}
			sortOrder = "ASC"
		}

		var statsBuilder strings.Builder

		if features["stats"] {
			buildServerStateStats(&statsBuilder, services)
		}
		if features["network"] {
			buildNetworkStats(&statsBuilder)
		}
		buildTrafficStats(&statsBuilder, memDB, dbMutex, mode, sortBy, sortOrder)

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

		user := r.URL.Query().Get("user")
		count := r.URL.Query().Get("count")

		if user == "" {
			http.Error(w, "Missing user parameter", http.StatusBadRequest)
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
		stats += fmt.Sprintf("%-12s %-6s %-s\n", "User", "Count", "Domain")
		stats += "-------------------------------------------------------------\n"
		rows, err := memDB.Query(`
			SELECT user AS "User", count AS "Count", domain AS "Domain"
			FROM dns_stats
			WHERE user = ?
			ORDER BY count DESC
			LIMIT ?`, user, count)
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var user, domain string
			var count int
			if err := rows.Scan(&user, &count, &domain); err != nil {
				log.Printf("Error reading result: %v", err)
				http.Error(w, "Error processing data", http.StatusInternalServerError)
				return
			}
			stats += fmt.Sprintf("%-12s %-6d %-s\n", user, count, domain)
		}

		fmt.Fprintln(w, stats)
	}
}

func UpdateIPLimitHandler(memDB *sql.DB, dbMutex *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
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

		query := "UPDATE clients_stats SET lim_ip = ? WHERE user = ?"
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

		log.Printf("IP address limit for user %s set to %d [%v]", userIdentifier, ipLimitInt, time.Since(start))
		w.WriteHeader(http.StatusOK)
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

		result, err := memDB.Exec("UPDATE clients_stats SET renew = ? WHERE user = ?", renew, userIdentifier)
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

func saveConfig(w http.ResponseWriter, configPath string, configData any, logMessage string) error {
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

func AddUserHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
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
		var configData any

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

		if err := saveConfig(w, configPath, configData, fmt.Sprintf("User %s added to configuration with inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
			log.Printf("Failed to add user %s: error saving configuration: %v [%v]", userIdentifier, err, time.Since(start))
			return
		}

		if cfg.Features["auth_lua"] {
			if err := lua.AddUserToAuthLua(cfg, userIdentifier, credential); err != nil {
				log.Printf("Failed to add user %s to auth.lua: %v", userIdentifier, err)
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}

func DeleteUserHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodDelete {
			http.Error(w, "Invalid method. Use DELETE", http.StatusMethodNotAllowed)
			return
		}

		userIdentifier := r.FormValue("user") // For Xray this is user, for Singbox this is name
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
				if err := saveConfig(w, configPath, mainConfig, fmt.Sprintf("User %s successfully removed from config.json, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
					return
				}

				if cfg.Features["auth_lua"] {
					if err := lua.DeleteUserFromAuthLua(cfg, userIdentifier); err != nil {
						log.Printf("Failed to delete user %s from auth.lua: %v", userIdentifier, err)
					} else {
						log.Printf("User %s successfully removed from auth.lua", userIdentifier)
					}
				}
				return
			}

			// Check and remove from .disabled_users
			disabledUpdated, removedFromDisabled := removeXrayUser(disabledConfig.Inbounds)
			if removedFromDisabled {
				disabledConfig.Inbounds = disabledUpdated
				if len(disabledConfig.Inbounds) > 0 {
					if err := saveConfig(w, disabledUsersPath, disabledConfig, fmt.Sprintf("User %s successfully removed from .disabled_users, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
						return
					}
				} else {
					if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
						log.Printf("Error removing empty .disabled_users: %v", err)
					}
				}

				if cfg.Features["auth_lua"] {
					if err := lua.DeleteUserFromAuthLua(cfg, userIdentifier); err != nil {
						log.Printf("Failed to delete user %s from auth.lua: %v", userIdentifier, err)
					} else {
						log.Printf("User %s successfully removed from auth.lua", userIdentifier)
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
				if err := saveConfig(w, configPath, mainConfig, fmt.Sprintf("User %s successfully removed from config.json, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
					return
				}

				if cfg.Features["auth_lua"] {
					if err := lua.DeleteUserFromAuthLua(cfg, userIdentifier); err != nil {
						log.Printf("Failed to delete user %s from auth.lua: %v", userIdentifier, err)
					} else {
						log.Printf("User %s successfully removed from auth.lua", userIdentifier)
					}
				}
				return
			}

			// Check and remove from .disabled_users
			disabledUpdated, removedFromDisabled := removeSingboxUser(disabledConfig.Inbounds)
			if removedFromDisabled {
				disabledConfig.Inbounds = disabledUpdated
				if len(disabledConfig.Inbounds) > 0 {
					if err := saveConfig(w, disabledUsersPath, disabledConfig, fmt.Sprintf("User %s successfully removed from .disabled_users, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
						return
					}
				} else {
					if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
						log.Printf("Error removing empty .disabled_users: %v", err)
					}
				}

				if cfg.Features["auth_lua"] {
					if err := lua.DeleteUserFromAuthLua(cfg, userIdentifier); err != nil {
						log.Printf("Failed to delete user %s from auth.lua: %v", userIdentifier, err)
					} else {
						log.Printf("User %s successfully removed from auth.lua", userIdentifier)
					}
				}
				return
			}

			// If user not found
			http.Error(w, fmt.Sprintf("User %s not found in inbound %s in either config.json or .disabled_users", userIdentifier, inboundTag), http.StatusNotFound)
		}
	}
}

func SetEnabledHandler(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) http.HandlerFunc {
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

		if err := db.ToggleUserEnabled(userIdentifier, enabled, cfg, memDB, dbMutex); err != nil {
			log.Printf("Error changing status: %v", err)
			http.Error(w, "Error updating status", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func updateSubscriptionDate(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config, userIdentifier, subEnd string) error {
	baseDate := time.Now().UTC()
	var subEndStr string

	err := memDB.QueryRow("SELECT sub_end FROM clients_stats WHERE user = ?", userIdentifier).Scan(&subEndStr)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("error querying database: %v", err)
	}
	if subEndStr != "" {
		baseDate, err = time.Parse("2006-01-02-15", subEndStr)
		if err != nil {
			return fmt.Errorf("error parsing sub_end: %v", err)
		}
	}

	err = db.AdjustDateOffset(memDB, dbMutex, userIdentifier, subEnd, baseDate)
	if err != nil {
		return fmt.Errorf("error updating date: %v", err)
	}

	go func() {
		db.CheckExpiredSubscriptions(memDB, dbMutex, cfg)
	}()

	return nil
}

func AdjustDateOffsetHandler(memDB *sql.DB, dbMutex *sync.Mutex, cfg *config.Config) http.HandlerFunc {
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
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
		userIdentifier := r.FormValue("user")
		subEnd := r.FormValue("sub_end")
		if userIdentifier == "" || subEnd == "" {
			http.Error(w, "user and sub_end are required", http.StatusBadRequest)
			return
		}

		err := updateSubscriptionDate(memDB, dbMutex, cfg, userIdentifier, subEnd)
		if err != nil {
			log.Printf("Error updating subscription for user %s: %v", userIdentifier, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = fmt.Fprintf(w, "Subscription date for %s updated with sub_end %s\n", userIdentifier, subEnd)
		if err != nil {
			log.Printf("Error writing response for user %s: %v", userIdentifier, err)
			http.Error(w, "Error sending response", http.StatusInternalServerError)
			return
		}
	}
}

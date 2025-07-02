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
	"v2ray-stat/stats"
)

type User struct {
	Email         string `json:"email"`
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

		rows, err := memDB.Query("SELECT email, uuid, rate, enabled, created, sub_end, renew, lim_ip, ips, uplink, downlink, sess_uplink, sess_downlink FROM clients_stats")
		if err != nil {
			log.Printf("Error executing SQL query: %v", err)
			http.Error(w, "Error executing query", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.Email, &user.Uuid, &user.Rate, &user.Enabled, &user.Created, &user.Sub_end, &user.Renew, &user.Lim_ip, &user.Ips, &user.Uplink, &user.Downlink, &user.Sess_uplink, &user.Sess_downlink); err != nil {
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
				uplink AS "Upload", 
				downlink AS "Download"
            FROM traffic_stats;
        `
		trafficColsServer = []string{"Upload", "Download"}
	case "standard", "extended":
		serverQuery = `
            SELECT source AS "Source", 
				sess_uplink AS "Sess Up", 
				sess_downlink AS "Sess Down",
				uplink AS "Upload", 
				downlink AS "Download"
            FROM traffic_stats;
        `
		trafficColsServer = []string{"Sess Up", "Sess Down", "Upload", "Download"}
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
            SELECT email AS "Email", rate AS "Rate", uplink AS "Uplink", downlink AS "Downlink"
            FROM clients_stats
            ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Uplink", "Downlink"}
	case "standard":
		clientQuery = fmt.Sprintf(`
            SELECT email AS "Email", 
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
            SELECT email AS "Email", 
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

	dbMutex.Lock()
	defer dbMutex.Unlock()

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
		validModes := []string{"minimal", "standard", "extended"}
		if !contains(validModes, mode) {
			if mode != "" {
				http.Error(w, fmt.Sprintf("Invalid mode parameter: %s, must be one of %v", mode, validModes), http.StatusBadRequest)
				return
			}
			mode = "minimal"
		}

		// Проверяем параметр sort_by
		sortBy := r.URL.Query().Get("sort_by")
		validSortColumns := []string{"email", "rate", "enabled", "sub_end", "renew", "sess_uplink", "sess_downlink", "uplink", "downlink", "lim_ip"}
		if !contains(validSortColumns, sortBy) {
			if sortBy != "" {
				http.Error(w, fmt.Sprintf("Invalid sort_by parameter: %s, must be one of %v", sortBy, validSortColumns), http.StatusBadRequest)
				return
			}
			sortBy = "email"
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

		stats := " 📊 DNS Query Statistics:\n"
		stats += fmt.Sprintf("%-12s %-6s %-s\n", "Email", "Count", "Domain")
		stats += "-------------------------------------------------------------\n"

		dbMutex.Lock()
		defer dbMutex.Unlock()

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

		query := "UPDATE clients_stats SET lim_ip = ? WHERE email = ?"
		
		dbMutex.Lock()
		defer dbMutex.Unlock()

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

	dbMutex.Lock()
	defer dbMutex.Unlock()

	err := memDB.QueryRow("SELECT sub_end FROM clients_stats WHERE email = ?", userIdentifier).Scan(&subEndStr)
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

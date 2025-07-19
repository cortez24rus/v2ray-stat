package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/constant"
	"v2ray-stat/db"
	dbpkg "v2ray-stat/db"
	"v2ray-stat/lua"
	"v2ray-stat/manager"
	"v2ray-stat/stats"
	"v2ray-stat/util"
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

func UsersHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		var users []User
		err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			rows, err := tx.Query("SELECT user, uuid, rate, enabled, created, sub_end, renew, lim_ip, ips, uplink, downlink, sess_uplink, sess_downlink FROM clients_stats")
			if err != nil {
				return fmt.Errorf("error executing SQL query: %v", err)
			}
			defer rows.Close()

			for rows.Next() {
				var user User
				if err := rows.Scan(&user.User, &user.Uuid, &user.Rate, &user.Enabled, &user.Created, &user.Sub_end, &user.Renew, &user.Lim_ip, &user.Ips, &user.Uplink, &user.Downlink, &user.Sess_uplink, &user.Sess_downlink); err != nil {
					return fmt.Errorf("error scanning row: %v", err)
				}
				users = append(users, user)
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("error iterating rows: %v", err)
			}
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in UsersHandler: %v [%v]", err, time.Since(start))
			http.Error(w, "Error processing data", http.StatusInternalServerError)
			return
		}

		if err := json.NewEncoder(w).Encode(users); err != nil {
			log.Printf("Error encoding JSON: %v [%v]", err, time.Since(start))
			http.Error(w, "Error forming response", http.StatusInternalServerError)
			return
		}
		log.Printf("UsersHandler completed successfully [%v]", time.Since(start))
	}
}

func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

func appendStats(builder *strings.Builder, content string) {
	builder.WriteString(content)
}

func formatTable(rows *sql.Rows, trafficColumns []string) (string, error) {
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
					unit := "byte"
					if columns[i] == "Rate" {
						unit = "bps"
					}
					strVal = util.FormatData(float64(numVal), unit)
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

func buildServerStateStats(builder *strings.Builder, services []string) {
	appendStats(builder, "➤  Server State:\n")
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Uptime:", stats.GetUptime()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Load average:", stats.GetLoadAverage()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Memory:", stats.GetMemoryUsage()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Disk usage:", stats.GetDiskUsage()))
	appendStats(builder, fmt.Sprintf("%-13s %s\n", "Status:", stats.GetStatus(services)))
	appendStats(builder, "\n")
}

func buildNetworkStats(builder *strings.Builder) {
	trafficMonitor := stats.GetTrafficMonitor()
	if trafficMonitor != nil {
		rxSpeed, txSpeed, rxPacketsPerSec, txPacketsPerSec, totalRxBytes, totalTxBytes := trafficMonitor.GetStats()
		appendStats(builder, fmt.Sprintf("➤  Network (%s):\n", trafficMonitor.Iface))
		appendStats(builder, fmt.Sprintf("rx: %s   %.0f p/s    %s\n", util.FormatData(float64(rxSpeed), "bps"), rxPacketsPerSec, util.FormatData(float64(totalRxBytes), "byte")))
		appendStats(builder, fmt.Sprintf("tx: %s   %.0f p/s    %s\n\n", util.FormatData(float64(txSpeed), "bps"), txPacketsPerSec, util.FormatData(float64(totalTxBytes), "byte")))
	}
}

func buildServerCustomStats(builder *strings.Builder, manager *manager.DatabaseManager, cfg *config.Config) error {
	serverColumnAliases := map[string]string{
		"source":        "Source",
		"rate":          "Rate",
		"uplink":        "Uplink",
		"downlink":      "Downlink",
		"sess_uplink":   "Sess Up",
		"sess_downlink": "Sess Down",
	}
	trafficAliases := []string{
		"Rate",
		"Uplink",
		"Downlink",
		"Sess Up",
		"Sess Down",
	}

	if len(cfg.StatsColumns.Server.Columns) > 0 {
		var serverCols []string
		for _, col := range cfg.StatsColumns.Server.Columns {
			if alias, ok := serverColumnAliases[col]; ok {
				serverCols = append(serverCols, fmt.Sprintf("%s AS \"%s\"", col, alias))
			}
		}
		serverQuery := fmt.Sprintf("SELECT %s FROM traffic_stats ORDER BY %s %s;",
			strings.Join(serverCols, ", "), cfg.StatsColumns.Server.SortBy, cfg.StatsColumns.Server.SortOrder)

		err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			rows, err := tx.Query(serverQuery)
			if err != nil {
				return fmt.Errorf("error executing custom server stats query: %v", err)
			}
			defer rows.Close()

			appendStats(builder, "➤  Server Statistics:\n")
			serverTable, err := formatTable(rows, trafficAliases)
			if err != nil {
				return fmt.Errorf("error formatting server stats table: %v", err)
			}
			appendStats(builder, serverTable)
			appendStats(builder, "\n")
			return tx.Commit()
		})

		if err != nil {
			return err
		}
	}
	return nil
}

func buildClientCustomStats(builder *strings.Builder, manager *manager.DatabaseManager, cfg *config.Config, sortBy, sortOrder string) error {
	clientColumnAliases := map[string]string{
		"user":          "User",
		"uuid":          "ID",
		"last_seen":     "Last seen",
		"rate":          "Rate",
		"uplink":        "Uplink",
		"downlink":      "Downlink",
		"sess_uplink":   "Sess Up",
		"sess_downlink": "Sess Down",
		"enabled":       "Enabled",
		"sub_end":       "Sub end",
		"renew":         "Renew",
		"lim_ip":        "Lim",
		"ips":           "Ips",
		"created":       "Created",
	}
	clientAliases := []string{
		"Rate",
		"Uplink",
		"Downlink",
		"Sess Up",
		"Sess Down",
	}

	if len(cfg.StatsColumns.Client.Columns) > 0 {
		var clientCols []string
		for _, col := range cfg.StatsColumns.Client.Columns {
			if alias, ok := clientColumnAliases[col]; ok {
				clientCols = append(clientCols, fmt.Sprintf("%s AS \"%s\"", col, alias))
			}
		}

		clientSortBy := cfg.StatsColumns.Client.SortBy
		if sortBy != "" {
			clientSortBy = sortBy
		}

		clientSortOrder := cfg.StatsColumns.Client.SortOrder
		if sortOrder != "" {
			clientSortOrder = sortOrder
		}

		clientQuery := fmt.Sprintf("SELECT %s FROM clients_stats ORDER BY %s %s;",
			strings.Join(clientCols, ", "), clientSortBy, clientSortOrder)

		err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			rows, err := tx.Query(clientQuery)
			if err != nil {
				return fmt.Errorf("error executing custom client stats query: %v", err)
			}
			defer rows.Close()

			appendStats(builder, "➤  Client Statistics:\n")
			clientTable, err := formatTable(rows, clientAliases)
			if err != nil {
				return fmt.Errorf("error formatting client stats table: %v", err)
			}
			appendStats(builder, clientTable)
			return tx.Commit()
		})

		if err != nil {
			return err
		}
	}
	return nil
}

func StatsCustomHandler(manager *manager.DatabaseManager, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		sortBy := r.URL.Query().Get("sort_by")
		validSortColumns := []string{"user", "uuid", "last_seen", "rate", "sess_uplink", "sess_downlink", "uplink", "downlink", "enabled", "sub_end", "renew", "lim_ip", "ips", "created"}
		if sortBy != "" && !contains(validSortColumns, sortBy) {
			http.Error(w, fmt.Sprintf("Invalid sort_by parameter: %s, must be one of %v", sortBy, validSortColumns), http.StatusBadRequest)
			return
		}

		sortOrder := r.URL.Query().Get("sort_order")
		if sortOrder != "" && sortOrder != "ASC" && sortOrder != "DESC" {
			http.Error(w, fmt.Sprintf("Invalid sort_order parameter: %s, must be ASC or DESC", sortOrder), http.StatusBadRequest)
			return
		}

		var statsBuilder strings.Builder

		if cfg.Features["system_monitoring"] {
			buildServerStateStats(&statsBuilder, cfg.Services)
		}
		if cfg.Features["network"] {
			buildNetworkStats(&statsBuilder)
		}

		if err := buildServerCustomStats(&statsBuilder, manager, cfg); err != nil {
			log.Printf("Server stats error: %v [%v]", err, time.Since(start))
			http.Error(w, "Server stats query failed", http.StatusInternalServerError)
			return
		}

		if err := buildClientCustomStats(&statsBuilder, manager, cfg, sortBy, sortOrder); err != nil {
			log.Printf("Client stats error: %v [%v]", err, time.Since(start))
			http.Error(w, "Client stats query failed", http.StatusInternalServerError)
			return
		}

		if statsBuilder.String() == "" {
			fmt.Fprintln(w, "No custom columns specified in config.")
			return
		}

		fmt.Fprintln(w, statsBuilder.String())
	}
}

func buildTrafficStats(builder *strings.Builder, manager *manager.DatabaseManager, mode, sortBy, sortOrder string) error {
	appendStats(builder, "➤  Server Statistics:\n")
	var serverQuery string
	var trafficColsServer []string
	switch mode {
	case "minimal", "standard":
		serverQuery = `
            SELECT source AS "Source",
                   rate AS "Rate",
                   uplink AS "Uplink",
                   downlink AS "Downlink"
            FROM traffic_stats;
        `
		trafficColsServer = []string{"Rate", "Uplink", "Downlink"}
	case "extended", "full":
		serverQuery = `
            SELECT source AS "Source",
                   rate AS "Rate",
                   sess_uplink AS "Sess Up",
                   sess_downlink AS "Sess Down",
                   uplink AS "Uplink",
                   downlink AS "Downlink"
            FROM traffic_stats;
        `
		trafficColsServer = []string{"Rate", "Sess Up", "Sess Down", "Uplink", "Downlink"}
	}

	err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("error starting transaction: %v", err)
		}
		defer tx.Rollback()

		rows, err := tx.Query(serverQuery)
		if err != nil {
			return fmt.Errorf("error executing server stats query: %v", err)
		}
		defer rows.Close()

		serverTable, err := formatTable(rows, trafficColsServer)
		if err != nil {
			return err
		}
		appendStats(builder, serverTable)
		return tx.Commit()
	})
	if err != nil {
		return err
	}

	appendStats(builder, "\n➤  Client Statistics:\n")
	var clientQuery string
	var trafficColsClients []string
	switch mode {
	case "minimal":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", 
                   last_seen AS "Last seen",
                   rate AS "Rate", 
                   uplink AS "Uplink", 
                   downlink AS "Downlink"
            FROM clients_stats
            ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Uplink", "Downlink"}
	case "standard":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", 
                   last_seen AS "Last seen",
                   rate AS "Rate", 
                   uplink AS "Uplink", 
                   downlink AS "Downlink", 
                   enabled AS "Enabled", 
                   sub_end AS "Sub end",
                   renew AS "Renew", 
                   lim_ip AS "Lim", 
                   ips AS "Ips"
            FROM clients_stats
            ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Uplink", "Downlink"}
	case "extended":
		clientQuery = fmt.Sprintf(`
            SELECT user AS "User", 
                   last_seen AS "Last seen",
                   rate AS "Rate", 
                   sess_uplink AS "Sess Up", 
                   sess_downlink AS "Sess Down",
                   uplink AS "Uplink", 
                   downlink AS "Downlink", 
                   enabled AS "Enabled", 
                   sub_end AS "Sub end",
                   renew AS "Renew", 
                   lim_ip AS "Lim", 
                   ips AS "Ips"
            FROM clients_stats
            ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Sess Up", "Sess Down", "Uplink", "Downlink"}
	case "full":
		clientQuery = fmt.Sprintf(`
			SELECT user AS "User", 
				   uuid AS "ID",
				   last_seen AS "Last seen",
				   rate AS "Rate",
				   sess_uplink AS "Sess Up", 
				   sess_downlink AS "Sess Down",
				   uplink AS "Uplink", 
				   downlink AS "Downlink", 
				   enabled AS "Enabled", 
				   sub_end AS "Sub end",
				   renew AS "Renew", 
				   lim_ip AS "Lim", 
				   ips AS "Ips",
				   created AS "Created"
		    FROM clients_stats
		    ORDER BY %s %s;`, sortBy, sortOrder)
		trafficColsClients = []string{"Rate", "Sess Up", "Sess Down", "Uplink", "Downlink"}
	}

	err = manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("error starting transaction: %v", err)
		}
		defer tx.Rollback()

		rows, err := tx.Query(clientQuery)
		if err != nil {
			return fmt.Errorf("error executing client stats query: %v", err)
		}
		defer rows.Close()

		clientTable, err := formatTable(rows, trafficColsClients)
		if err != nil {
			return err
		}
		appendStats(builder, clientTable)
		return tx.Commit()
	})
	return err
}

func StatsHandler(manager *manager.DatabaseManager, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		mode := r.URL.Query().Get("mode")
		validModes := []string{"minimal", "standard", "extended", "full"}
		if !contains(validModes, mode) {
			if mode != "" {
				http.Error(w, fmt.Sprintf("Invalid mode parameter: %s, must be one of %v", mode, validModes), http.StatusBadRequest)
				return
			}
			mode = "minimal"
		}

		sortBy := r.URL.Query().Get("sort_by")
		validSortColumns := []string{"user", "uuid", "last_seen", "rate", "sess_uplink", "sess_downlink", "uplink", "downlink", "enabled", "sub_end", "renew", "lim_ip", "ips", "created"}
		if sortBy != "" && !contains(validSortColumns, sortBy) {
			http.Error(w, fmt.Sprintf("Invalid sort_by parameter: %s, must be one of %v", sortBy, validSortColumns), http.StatusBadRequest)
			return
		}

		sortOrder := r.URL.Query().Get("sort_order")
		if sortOrder != "" && sortOrder != "ASC" && sortOrder != "DESC" {
			http.Error(w, fmt.Sprintf("Invalid sort_order parameter: %s, must be ASC or DESC", sortOrder), http.StatusBadRequest)
			return
		}

		var statsBuilder strings.Builder

		if cfg.Features["system_monitoring"] {
			buildServerStateStats(&statsBuilder, cfg.Services)
		}
		if cfg.Features["network"] {
			buildNetworkStats(&statsBuilder)
		}

		if err := buildTrafficStats(&statsBuilder, manager, mode, sortBy, sortOrder); err != nil {
			log.Printf("Error building traffic stats: %v [%v]", err, time.Since(start))
			http.Error(w, "Error processing stats", http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, statsBuilder.String())
		log.Printf("StatsHandler completed successfully [%v]", time.Since(start))
	}
}

func ResetTrafficHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		trafficMonitor := stats.GetTrafficMonitor()
		if trafficMonitor == nil {
			log.Printf("Traffic monitor not initialized [%v]", time.Since(start))
			http.Error(w, "Traffic monitor not initialized", http.StatusInternalServerError)
			return
		}

		err := trafficMonitor.ResetTraffic()
		if err != nil {
			log.Printf("Failed to reset traffic: %v [%v]", err, time.Since(start))
			http.Error(w, fmt.Sprintf("Failed to reset traffic: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Traffic reset successfully [%v]", time.Since(start))
		w.WriteHeader(http.StatusOK)
	}
}

func DnsStatsHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Invalid method. Use GET", http.StatusMethodNotAllowed)
			return
		}

		user := r.URL.Query().Get("user")
		count := r.URL.Query().Get("count")

		if user == "" {
			log.Printf("Missing user parameter [%v]", time.Since(start))
			http.Error(w, "Missing user parameter", http.StatusBadRequest)
			return
		}

		if count == "" {
			count = "20"
		}

		if _, err := strconv.Atoi(count); err != nil {
			log.Printf("Invalid count parameter: %s [%v]", count, time.Since(start))
			http.Error(w, "Invalid count parameter", http.StatusBadRequest)
			return
		}

		var statsBuilder strings.Builder
		statsBuilder.WriteString(" 📊 DNS Query Statistics:\n")
		statsBuilder.WriteString(fmt.Sprintf("%-12s %-6s %-s\n", "User", "Count", "Domain"))
		statsBuilder.WriteString("-------------------------------------------------------------\n")

		err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			rows, err := tx.Query(`
				SELECT user AS "User", count AS "Count", domain AS "Domain"
				FROM dns_stats
				WHERE user = ?
				ORDER BY count DESC
				LIMIT ?`, user, count)
			if err != nil {
				return fmt.Errorf("error executing SQL query: %v", err)
			}
			defer rows.Close()

			for rows.Next() {
				var user, domain string
				var count int
				if err := rows.Scan(&user, &count, &domain); err != nil {
					return fmt.Errorf("error scanning row: %v", err)
				}
				statsBuilder.WriteString(fmt.Sprintf("%-12s %-6d %-s\n", user, count, domain))
			}
			if err := rows.Err(); err != nil {
				return fmt.Errorf("error iterating rows: %v", err)
			}
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in DnsStatsHandler: %v [%v]", err, time.Since(start))
			http.Error(w, "Error processing data", http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, statsBuilder.String())
		log.Printf("DnsStatsHandler completed successfully [%v]", time.Since(start))
	}
}

func UpdateIPLimitHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			log.Printf("Error parsing form: %v [%v]", err, time.Since(start))
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		userIdentifier := r.FormValue("user")
		ipLimit := r.FormValue("lim_ip")

		if userIdentifier == "" {
			log.Printf("Invalid parameters: user is required [%v]", time.Since(start))
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
				log.Printf("Invalid lim_ip parameter: %s [%v]", ipLimit, time.Since(start))
				http.Error(w, "lim_ip must be a number", http.StatusBadRequest)
				return
			}

			if ipLimitInt < 0 || ipLimitInt > 100 {
				log.Printf("Invalid lim_ip value: %d, must be between 1 and 100 [%v]", ipLimitInt, time.Since(start))
				http.Error(w, "lim_ip must be between 1 and 100", http.StatusBadRequest)
				return
			}
		}

		err = manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			result, err := tx.Exec("UPDATE clients_stats SET lim_ip = ? WHERE user = ?", ipLimitInt, userIdentifier)
			if err != nil {
				return fmt.Errorf("error updating lim_ip for user %s: %v", userIdentifier, err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("error checking rows affected for user %s: %v", userIdentifier, err)
			}

			if rowsAffected == 0 {
				return fmt.Errorf("user '%s' not found", userIdentifier)
			}
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in UpdateIPLimitHandler: %v [%v]", err, time.Since(start))
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		log.Printf("IP address limit for user %s set to %d [%v]", userIdentifier, ipLimitInt, time.Since(start))
		w.WriteHeader(http.StatusOK)
	}
}

func DeleteDNSStatsHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			result, err := tx.Exec("DELETE FROM dns_stats")
			if err != nil {
				return fmt.Errorf("error deleting records from dns_stats: %v", err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("error checking rows affected: %v", err)
			}

			log.Printf("Received request to delete dns_stats from %s, %d rows affected [%v]", r.RemoteAddr, rowsAffected, time.Since(start))
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in DeleteDNSStatsHandler: %v [%v]", err, time.Since(start))
			http.Error(w, "Failed to delete records from dns_stats", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func ResetTrafficStatsHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			result, err := tx.Exec("UPDATE traffic_stats SET uplink = 0, downlink = 0")
			if err != nil {
				return fmt.Errorf("error resetting traffic statistics: %v", err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("error retrieving number of affected rows: %v", err)
			}

			log.Printf("Received request to reset traffic_stats from %s, affected %d rows [%v]", r.RemoteAddr, rowsAffected, time.Since(start))
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in ResetTrafficStatsHandler: %v [%v]", err, time.Since(start))
			http.Error(w, "Failed to reset traffic statistics", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func ResetClientsStatsHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method. Use POST", http.StatusMethodNotAllowed)
			return
		}

		err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			result, err := tx.Exec("UPDATE clients_stats SET uplink = 0, downlink = 0")
			if err != nil {
				return fmt.Errorf("error resetting traffic statistics: %v", err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("error retrieving number of affected rows: %v", err)
			}

			log.Printf("Received request to reset clients_stats from %s, affected %d rows [%v]", r.RemoteAddr, rowsAffected, time.Since(start))
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in ResetClientsStatsHandler: %v [%v]", err, time.Since(start))
			http.Error(w, "Failed to reset traffic statistics", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func UpdateRenewHandler(manager *manager.DatabaseManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v [%v]", err, time.Since(start))
			http.Error(w, "Error parsing data", http.StatusBadRequest)
			return
		}

		userIdentifier := r.FormValue("user")
		renewStr := r.FormValue("renew")

		if userIdentifier == "" {
			log.Printf("user is required [%v]", time.Since(start))
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
				log.Printf("Invalid renew parameter: %s [%v]", renewStr, time.Since(start))
				http.Error(w, "renew must be an integer", http.StatusBadRequest)
				return
			}
			if renew < 0 {
				log.Printf("Invalid renew value: %d, cannot be negative [%v]", renew, time.Since(start))
				http.Error(w, "renew cannot be negative", http.StatusBadRequest)
				return
			}
		}

		err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			result, err := tx.Exec("UPDATE clients_stats SET renew = ? WHERE user = ?", renew, userIdentifier)
			if err != nil {
				return fmt.Errorf("error updating renew for %s: %v", userIdentifier, err)
			}

			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("error getting RowsAffected: %v", err)
			}

			if rowsAffected == 0 {
				return fmt.Errorf("user '%s' not found", userIdentifier)
			}
			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in UpdateRenewHandler: %v [%v]", err, time.Since(start))
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		log.Printf("Auto-renewal set to %d for user %s [%v]", renew, userIdentifier, time.Since(start))
		w.WriteHeader(http.StatusOK)
	}
}

func AddUserToConfig(user, credential, inboundTag string, cfg *config.Config) error {
	start := time.Now()
	configPath := cfg.Core.Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("error reading config.json: %v", err)
	}

	proxyType := cfg.V2rayStat.Type
	var configData any
	var protocol string

	switch proxyType {
	case "xray":
		var cfgXray config.ConfigXray
		if err := json.Unmarshal(data, &cfgXray); err != nil {
			return fmt.Errorf("error parsing JSON: %v", err)
		}

		found := false
		for i, inbound := range cfgXray.Inbounds {
			if inbound.Tag == inboundTag {
				protocol = inbound.Protocol
				for _, client := range inbound.Settings.Clients {
					if protocol == "vless" && client.ID == credential {
						return fmt.Errorf("user with this id already exists")
					} else if protocol == "trojan" && client.Password == credential {
						return fmt.Errorf("user with this password already exists")
					}
				}
				newClient := config.XrayClient{Email: user}
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
			return fmt.Errorf("inbound with tag %s not found", inboundTag)
		}
		configData = cfgXray

	case "singbox":
		var cfgSingBox config.ConfigSingbox
		if err := json.Unmarshal(data, &cfgSingBox); err != nil {
			return fmt.Errorf("error parsing JSON: %v", err)
		}

		found := false
		for i, inbound := range cfgSingBox.Inbounds {
			if inbound.Tag == inboundTag {
				protocol = inbound.Type
				for _, user := range inbound.Users {
					if protocol == "vless" && user.UUID == credential {
						return fmt.Errorf("user with this uuid already exists")
					} else if protocol == "trojan" && user.Password == credential {
						return fmt.Errorf("user with this password already exists")
					}
				}
				newUser := config.SingboxClient{Name: user}
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
			return fmt.Errorf("inbound with tag %s not found", inboundTag)
		}
		configData = cfgSingBox

	default:
		return fmt.Errorf("unsupported core type: %s", proxyType)
	}

	updateData, err := json.MarshalIndent(configData, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}
	if err := os.WriteFile(configPath, updateData, 0644); err != nil {
		return fmt.Errorf("error writing config.json: %v", err)
	}

	log.Printf("User %s added to configuration with inbound %s [%v]", user, inboundTag, time.Since(start))

	if cfg.Features["auth_lua"] {
		var credentialToAdd string
		if protocol == "trojan" {
			hash := sha256.Sum224([]byte(credential))
			credentialToAdd = hex.EncodeToString(hash[:])
		} else {
			credentialToAdd = credential
		}
		if err := lua.AddUserToAuthLua(cfg, user, credentialToAdd); err != nil {
			log.Printf("Failed to add user %s to auth.lua: %v [%v]", user, err, time.Since(start))
		}
	}

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
			log.Printf("Error parsing form data: %v [%v]", err, time.Since(start))
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		userIdentifier := r.FormValue("user")
		credential := r.FormValue("credential")
		inboundTag := r.FormValue("inboundTag")
		if userIdentifier == "" || credential == "" {
			log.Printf("Error: user and credential parameters are missing or empty [%v]", time.Since(start))
			http.Error(w, "user and credential are required", http.StatusBadRequest)
			return
		}
		if inboundTag == "" {
			inboundTag = "vless-in"
			log.Printf("inboundTag parameter not specified, using default value: %s [%v]", inboundTag, time.Since(start))
		}

		err := AddUserToConfig(userIdentifier, credential, inboundTag, cfg)
		if err != nil {
			log.Printf("Failed to add user %s: %v [%v]", userIdentifier, err, time.Since(start))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		log.Printf("AddUserHandler completed successfully for user %s [%v]", userIdentifier, time.Since(start))
	}
}

func saveConfig(w http.ResponseWriter, configPath string, configData any, logMessage string) error {
	updateData, err := json.MarshalIndent(configData, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		if w != nil {
			http.Error(w, "Error updating configuration", http.StatusInternalServerError)
		}
		return err
	}

	if err := os.WriteFile(configPath, updateData, 0644); err != nil {
		log.Printf("Error writing config.json: %v", err)
		if w != nil {
			http.Error(w, "Error saving configuration", http.StatusInternalServerError)
		}
		return err
	}

	log.Print(logMessage)
	return nil
}

func DeleteUserFromConfig(userIdentifier, inboundTag string, cfg *config.Config) error {
	start := time.Now()
	configPath := cfg.Core.Config
	disabledUsersPath := filepath.Join(cfg.Core.Dir, ".disabled_users")
	proxyType := cfg.V2rayStat.Type

	var userRemoved bool

	switch proxyType {
	case "xray":
		mainConfigData, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("error reading config.json: %v", err)
		}
		var mainConfig config.ConfigXray
		if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
			return fmt.Errorf("error parsing JSON for config.json: %v", err)
		}

		var disabledConfig config.DisabledUsersConfigXray
		disabledConfigData, err := os.ReadFile(disabledUsersPath)
		if err == nil && len(disabledConfigData) > 0 {
			if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
				return fmt.Errorf("error parsing JSON for .disabled_users: %v", err)
			}
		} else {
			disabledConfig = config.DisabledUsersConfigXray{Inbounds: []config.XrayInbound{}}
		}

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

		mainUpdated, removedFromMain := removeXrayUser(mainConfig.Inbounds)
		if removedFromMain {
			mainConfig.Inbounds = mainUpdated
			if err := saveConfig(nil, configPath, mainConfig, fmt.Sprintf("User %s successfully removed from config.json, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
				return err
			}
			userRemoved = true
		}

		disabledUpdated, removedFromDisabled := removeXrayUser(disabledConfig.Inbounds)
		if removedFromDisabled {
			disabledConfig.Inbounds = disabledUpdated
			if len(disabledConfig.Inbounds) > 0 {
				if err := saveConfig(nil, disabledUsersPath, disabledConfig, fmt.Sprintf("User %s successfully removed from .disabled_users, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
					return err
				}
			} else {
				if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("error removing empty .disabled_users: %v", err)
				}
				log.Printf("User %s successfully removed from .disabled_users, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))
			}
			userRemoved = true
		}

	case "singbox":
		mainConfigData, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("error reading config.json: %v", err)
		}
		var mainConfig config.ConfigSingbox
		if err := json.Unmarshal(mainConfigData, &mainConfig); err != nil {
			return fmt.Errorf("error parsing JSON for config.json: %v", err)
		}

		var disabledConfig config.DisabledUsersConfigSingbox
		disabledConfigData, err := os.ReadFile(disabledUsersPath)
		if err == nil && len(disabledConfigData) > 0 {
			if err := json.Unmarshal(disabledConfigData, &disabledConfig); err != nil {
				return fmt.Errorf("error parsing JSON for .disabled_users: %v", err)
			}
		} else {
			disabledConfig = config.DisabledUsersConfigSingbox{Inbounds: []config.SingboxInbound{}}
		}

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

		mainUpdated, removedFromMain := removeSingboxUser(mainConfig.Inbounds)
		if removedFromMain {
			mainConfig.Inbounds = mainUpdated
			if err := saveConfig(nil, configPath, mainConfig, fmt.Sprintf("User %s successfully removed from config.json, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
				return err
			}
			userRemoved = true
		}

		disabledUpdated, removedFromDisabled := removeSingboxUser(disabledConfig.Inbounds)
		if removedFromDisabled {
			disabledConfig.Inbounds = disabledUpdated
			if len(disabledConfig.Inbounds) > 0 {
				if err := saveConfig(nil, disabledUsersPath, disabledConfig, fmt.Sprintf("User %s successfully removed from .disabled_users, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))); err != nil {
					return err
				}
			} else {
				if err := os.Remove(disabledUsersPath); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("error removing empty .disabled_users: %v", err)
				}
				log.Printf("User %s successfully removed from .disabled_users, inbound %s [%v]", userIdentifier, inboundTag, time.Since(start))
			}
			userRemoved = true
		}
	}

	if userRemoved && cfg.Features["auth_lua"] {
		if err := lua.DeleteUserFromAuthLua(cfg, userIdentifier); err != nil {
			log.Printf("Failed to delete user %s from auth.lua: %v [%v]", userIdentifier, err, time.Since(start))
		} else {
			log.Printf("User %s successfully removed from auth.lua [%v]", userIdentifier, time.Since(start))
		}
	}

	if !userRemoved {
		return fmt.Errorf("user %s not found in inbound %s in either config.json or .disabled_users", userIdentifier, inboundTag)
	}

	return nil
}

func DeleteUserHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodDelete {
			http.Error(w, "Invalid method. Use DELETE", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v [%v]", err, time.Since(start))
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		userIdentifier := r.FormValue("user")
		inboundTag := r.FormValue("inboundTag")
		if userIdentifier == "" {
			log.Printf("Error: user parameter is missing or empty [%v]", time.Since(start))
			http.Error(w, "user parameter is required", http.StatusBadRequest)
			return
		}
		if inboundTag == "" {
			inboundTag = "vless-in"
			log.Printf("inboundTag parameter not specified, using default value: %s [%v]", inboundTag, time.Since(start))
		}

		err := DeleteUserFromConfig(userIdentifier, inboundTag, cfg)
		if err != nil {
			log.Printf("Failed to delete user %s: %v [%v]", userIdentifier, err, time.Since(start))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		log.Printf("DeleteUserHandler completed successfully for user %s [%v]", userIdentifier, time.Since(start))
	}
}

func SetEnabledHandler(manager *manager.DatabaseManager, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v [%v]", err, time.Since(start))
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}

		userIdentifier := r.FormValue("user")
		enabledStr := r.FormValue("enabled")

		if userIdentifier == "" {
			log.Printf("user is required [%v]", time.Since(start))
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
				log.Printf("Invalid enabled parameter: %s [%v]", enabledStr, time.Since(start))
				http.Error(w, "enabled must be true or false", http.StatusBadRequest)
				return
			}
		}

		err := manager.ExecuteHighPriority(func(db *sql.DB) error { // Высокий приоритет, так как это операция записи
			tx, err := db.Begin()
			if err != nil {
				return fmt.Errorf("error starting transaction: %v", err)
			}
			defer tx.Rollback()

			// Call db.ToggleUserEnabled from the db package
			if err := dbpkg.ToggleUserEnabled(userIdentifier, enabled, cfg, manager); err != nil {
				return fmt.Errorf("error toggling user enabled status: %v", err)
			}

			enabledStr := "false"
			if enabled {
				enabledStr = "true"
			}
			_, err = tx.Exec("UPDATE clients_stats SET enabled = ? WHERE user = ?", enabledStr, userIdentifier)
			if err != nil {
				return fmt.Errorf("error updating enabled status for %s: %v", userIdentifier, err)
			}

			return tx.Commit()
		})

		if err != nil {
			log.Printf("Error in SetEnabledHandler: %v [%v]", err, time.Since(start))
			http.Error(w, "Error updating status", http.StatusInternalServerError)
			return
		}

		log.Printf("User %s enabled status set to %v [%v]", userIdentifier, enabled, time.Since(start))
		w.WriteHeader(http.StatusOK)
	}
}

func updateSubscriptionDate(manager *manager.DatabaseManager, cfg *config.Config, userIdentifier, subEnd string) error {
	start := time.Now()
	baseDate := time.Now().UTC()
	var subEndStr string

	err := manager.Execute(func(db *sql.DB) error { // Низкий приоритет, так как это операция чтения
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("error starting transaction: %v", err)
		}
		defer tx.Rollback()

		err = tx.QueryRow("SELECT sub_end FROM clients_stats WHERE user = ?", userIdentifier).Scan(&subEndStr)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("error querying database: %v", err)
		}
		return tx.Commit()
	})
	if err != nil {
		return fmt.Errorf("error querying subscription date: %v [%v]", err, time.Since(start))
	}

	if subEndStr != "" {
		var err error
		baseDate, err = time.Parse("2006-01-02-15", subEndStr)
		if err != nil {
			return fmt.Errorf("error parsing sub_end: %v [%v]", err, time.Since(start))
		}
	}

	err = db.AdjustDateOffset(manager, userIdentifier, subEnd, baseDate)
	if err != nil {
		return fmt.Errorf("error updating date: %v [%v]", err, time.Since(start))
	}

	go func() {
		if err := db.CheckExpiredSubscriptions(manager, cfg); err != nil {
			log.Printf("Error checking expired subscriptions: %v [%v]", err, time.Since(start))
		}
	}()

	log.Printf("Subscription date for user %s updated successfully [%v]", userIdentifier, time.Since(start))
	return nil
}

func AdjustDateOffsetHandler(manager *manager.DatabaseManager, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPatch {
			http.Error(w, "Invalid method. Use PATCH", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form data: %v [%v]", err, time.Since(start))
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
		userIdentifier := r.FormValue("user")
		subEnd := r.FormValue("sub_end")
		if userIdentifier == "" || subEnd == "" {
			log.Printf("user and sub_end are required [%v]", time.Since(start))
			http.Error(w, "user and sub_end are required", http.StatusBadRequest)
			return
		}

		err := updateSubscriptionDate(manager, cfg, userIdentifier, subEnd)
		if err != nil {
			log.Printf("Error updating subscription for user %s: %v [%v]", userIdentifier, err, time.Since(start))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = fmt.Fprintf(w, "Subscription date for %s updated with sub_end %s\n", userIdentifier, subEnd)
		if err != nil {
			log.Printf("Error writing response for user %s: %v [%v]", userIdentifier, err, time.Since(start))
			http.Error(w, "Error sending response", http.StatusInternalServerError)
			return
		}
		log.Printf("AdjustDateOffsetHandler completed successfully for user %s [%v]", userIdentifier, time.Since(start))
	}
}

func Answer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverHeader := fmt.Sprintf("MuxCloud/%s (WebServer)", constant.Version)
		w.Header().Set("Server", serverHeader)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Powered-By", "MuxCloud")
		fmt.Fprintf(w, "MuxCloud / %s\n", constant.Version)
	}
}

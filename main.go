package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
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
	"v2ray-stat/telegram"

	_ "github.com/mattn/go-sqlite3"
	statsSingbox "github.com/v2ray/v2ray-core/app/stats/command"
	statsXray "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	Version             string
	dnsEnabled          = flag.Bool("dns", false, "Enable DNS statistics collection")
	statsEnabled        = flag.Bool("stats", false, "Enable general server statistics output")
	networkEnabled      = flag.Bool("net", false, "Enable network interface statistics collection")
	uniqueEntries       = make(map[string]map[string]time.Time)
	uniqueEntriesMutex  sync.Mutex
	renewNotifiedUsers  = make(map[string]bool)
	dbMutex             sync.Mutex
	previousStats       string
	clientPreviousStats string
	notifiedUsers       = make(map[string]bool)
	notifiedMutex       sync.Mutex
	trafficMonitor      *stats.TrafficMonitor
)

var (
	accessLogRegex  = regexp.MustCompile(`from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`)
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
)

func getDefaultInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	count := 0
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}

		count++
		if count == 2 {
			return i.Name, nil
		}
	}

	return "", fmt.Errorf("second active interface not found")
}

func getApiResponse(cfg *config.Config) (*api.ApiResponse, error) {
	clientConn, err := grpc.NewClient("127.0.0.1:9953", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("error connecting to gRPC server: %w", err)
	}
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stats []api.Stat

	switch cfg.CoreType {
	case "xray":
		client := statsXray.NewStatsServiceClient(clientConn)
		req := &statsXray.QueryStatsRequest{
			Pattern: "",
		}
		xrayResp, err := client.QueryStats(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("error executing gRPC request for Xray: %w", err)
		}

		for _, s := range xrayResp.GetStat() {
			stats = append(stats, api.Stat{
				Name:  s.GetName(),
				Value: strconv.FormatInt(s.GetValue(), 10),
			})
		}

	case "singbox":
		client := statsSingbox.NewStatsServiceClient(clientConn)
		req := &statsSingbox.QueryStatsRequest{
			Pattern: "",
		}
		singboxResp, err := client.QueryStats(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("error executing gRPC request for Singbox: %w", err)
		}
		for _, s := range singboxResp.GetStat() {
			stats = append(stats, api.Stat{
				Name:  s.GetName(),
				Value: strconv.FormatInt(s.GetValue(), 10),
			})
		}
	}

	return &api.ApiResponse{Stat: stats}, nil
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

func updateProxyStats(memDB *sql.DB, apiData *api.ApiResponse) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

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
		diff := current - previous
		if diff < 0 {
			diff = 0
		}

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
		log.Printf("No new data to add or update")
	}

	previousStats = strings.Join(currentStats, "\n")
}

func updateClientStats(memDB *sql.DB, apiData *api.ApiResponse) {
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
		diff := current - previous
		if diff < 0 {
			diff = 0
		}

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

		uplinkOnline := sessUplink - previousUplink
		downlinkOnline := sessDownlink - previousDownlink
		diffOnline := uplinkOnline + downlinkOnline

		var onlineStatus string
		switch {
		case diffOnline < 1:
			onlineStatus = "offline"
		case diffOnline < 24576:
			onlineStatus = "idle"
		case diffOnline < 18874368:
			onlineStatus = "online"
		default:
			onlineStatus = "overload"
		}

		queries += fmt.Sprintf("INSERT OR REPLACE INTO clients_stats (email, status, uplink, downlink, sess_uplink, sess_downlink) "+
			"VALUES ('%s', '%s', %d, %d, %d, %d) ON CONFLICT(email) DO UPDATE SET "+
			"status = '%s', uplink = uplink + %d, downlink = downlink + %d, "+
			"sess_uplink = %d, sess_downlink = %d;\n",
			email, onlineStatus, uplink, downlink, sessUplink, sessDownlink,
			onlineStatus, uplink, downlink, sessUplink, sessDownlink)
	}

	if queries != "" {
		_, err := memDB.Exec(queries)
		if err != nil {
			log.Printf("Error executing transaction: %v", err)
		}
	} else {
		log.Printf("No new data to add or update")
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

func updateEnabledInDB(memDB *sql.DB, email string, enabled bool) {
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

type DNSStat struct {
	Email  string
	Domain string
	Count  int
}

func upsertDNSRecordsBatch(tx *sql.Tx, dnsStats map[string]map[string]int) error {
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

func processLogLine(tx *sql.Tx, line string, dnsStats map[string]map[string]int, cfg *config.Config) {
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

	if err := db.UpdateIPInDB(tx, email, validIPs); err != nil {
		log.Printf("Error updating IP in database: %v", err)
	}

	if *dnsEnabled {
		if dnsStats[email] == nil {
			dnsStats[email] = make(map[string]int)
		}
		dnsStats[email][domain]++
	}
}

func readNewLines(memDB *sql.DB, file *os.File, offset *int64, cfg *config.Config) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	file.Seek(*offset, 0)
	scanner := bufio.NewScanner(file)

	tx, err := memDB.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		return
	}

	dnsStats := make(map[string]map[string]int)

	for scanner.Scan() {
		processLogLine(tx, scanner.Text(), dnsStats, cfg)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file: %v", err)
		tx.Rollback()
		return
	}

	if *dnsEnabled && len(dnsStats) > 0 {
		if err := upsertDNSRecordsBatch(tx, dnsStats); err != nil {
			log.Printf("Error during batch update of DNS queries: %v", err)
			tx.Rollback()
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		tx.Rollback()
		return
	}

	pos, err := file.Seek(0, 1)
	if err != nil {
		log.Printf("Error retrieving file position: %v", err)
		return
	}
	*offset = pos
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

func checkExpiredSubscriptions(memDB *sql.DB, cfg *config.Config) {
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
					err = adjustDateOffset(memDB, s.Email, offset, now)
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
						err = api.ToggleUserEnabled(s.Email, true, cfg, memDB)
						if err != nil {
							log.Printf("Error enabling user %s: %v", s.Email, err)
							continue
						}
						updateEnabledInDB(memDB, s.Email, true)
						log.Printf("User %s enabled", s.Email)
					}
				} else if s.Enabled == "true" {
					err = api.ToggleUserEnabled(s.Email, false, cfg, memDB)
					if err != nil {
						log.Printf("Error disabling user %s: %v", s.Email, err)
					} else {
						log.Printf("User %s disabled", s.Email)
					}
					updateEnabledInDB(memDB, s.Email, false)
				}
			} else {
				if s.Enabled == "false" {
					err = api.ToggleUserEnabled(s.Email, true, cfg, memDB)
					if err != nil {
						log.Printf("Error enabling user %s: %v", s.Email, err)
						continue
					}
					updateEnabledInDB(memDB, s.Email, true)
					log.Printf("✅ Subscription resumed, user %s enabled (%s)", s.Email, s.SubEnd)
				}
			}
		}
	}
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

func adjustDateOffset(memDB *sql.DB, email, offset string, baseDate time.Time) error {
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

	log.Printf("Subscription date for %s updated: %s -> %s (offset: %s)", email, baseDate.Format("2006-01-02-15"), newDate.Format("2006-01-02-15"), offset)
	return nil
}

func adjustDateOffsetHandler(memDB *sql.DB, cfg *config.Config) http.HandlerFunc {
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
		sub_end := r.FormValue("sub_end")
		if userIdentifier == "" || sub_end == "" {
			http.Error(w, "user and sub_end are required", http.StatusBadRequest)
			return
		}

		dbMutex.Lock()
		baseDate := time.Now().UTC()
		var subEndStr string
		err := memDB.QueryRow("SELECT sub_end FROM clients_stats WHERE email = ?", userIdentifier).Scan(&subEndStr)
		if err != nil && err != sql.ErrNoRows {
			dbMutex.Unlock()
			log.Printf("Error querying database: %v", err)
			http.Error(w, "Error querying database", http.StatusInternalServerError)
			return
		}
		if subEndStr != "" {
			baseDate, err = time.Parse("2006-01-02-15", subEndStr)
			if err != nil {
				dbMutex.Unlock()
				log.Printf("Error parsing sub_end: %v", err)
				http.Error(w, "Error parsing sub_end", http.StatusInternalServerError)
				return
			}
		}
		err = adjustDateOffset(memDB, userIdentifier, sub_end, baseDate)
		dbMutex.Unlock()

		if err != nil {
			log.Printf("Error updating date: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		go func() {
			checkExpiredSubscriptions(memDB, cfg)
		}()

		w.WriteHeader(http.StatusOK)
		_, err = fmt.Fprintf(w, "Subscription date for %s updated with sub_end %s\n", userIdentifier, sub_end)
		if err != nil {
			log.Printf("Error writing response for user %s: %v", userIdentifier, err)
			http.Error(w, "Error sending response", http.StatusInternalServerError)
			return
		}
	}
}

func startAPIServer(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	server := &http.Server{
		Addr:    "127.0.0.1:" + cfg.Port,
		Handler: nil,
	}

	http.HandleFunc("/api/v1/stats", api.StatsHandler(memDB, &dbMutex, statsEnabled, networkEnabled, trafficMonitor, cfg.Services))

	http.HandleFunc("/api/v1/users", api.UsersHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/add_user", api.AddUserHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/delete_user", api.DeleteUserHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/set_enabled", api.SetEnabledHandler(memDB, cfg))

	http.HandleFunc("/api/v1/dns_stats", api.DnsStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/delete_dns_stats", api.DeleteDNSStatsHandler(memDB, &dbMutex))

	http.HandleFunc("/api/v1/reset_traffic", api.ResetTrafficHandler(trafficMonitor))
	http.HandleFunc("/api/v1/reset_clients_stats", api.ResetClientsStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/reset_traffic_stats", api.ResetTrafficStatsHandler(memDB, &dbMutex))

	http.HandleFunc("/api/v1/update_lim_ip", api.UpdateIPLimitHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/adjust_date", adjustDateOffsetHandler(memDB, cfg))
	http.HandleFunc("/api/v1/update_renew", api.UpdateRenewHandler(memDB, &dbMutex))

	go func() {
		log.Printf("API server starting on 127.0.0.1:%s...", cfg.Port)
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
	log.Println("API server stopped successfully")

	wg.Done()
}

func cleanInvalidTrafficTags(memDB *sql.DB, cfg *config.Config) error {
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

// Инициализация базы данных
func initDatabase(cfg *config.Config) (memDB *sql.DB, accessLog, bannedLog *os.File, offset, bannedOffset *int64, err error) {
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

// Запуск задачи синхронизации базы и проверки подписок
func monitorSubscriptionsAndSync(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := cleanInvalidTrafficTags(memDB, cfg); err != nil {
					log.Printf("Error cleaning non-existent tags: %v", err)
				}
				checkExpiredSubscriptions(memDB, cfg)

				if err := db.SyncToFileDB(memDB, cfg); err != nil {
					log.Printf("Error synchronizing: %v", err)
				} else {
					log.Println("Database synchronized successfully")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Запуск задачи мониторинга пользователей и логов
func monitorUsersAndLogs(ctx context.Context, memDB *sql.DB, accessLog *os.File, offset *int64, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
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

				apiData, err := getApiResponse(cfg)
				if err != nil {
					log.Printf("Error retrieving API data: %v", err)
				} else {
					updateProxyStats(memDB, apiData)
					updateClientStats(memDB, apiData)
				}
				readNewLines(memDB, accessLog, offset, cfg)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Инициализация мониторинга сети
func initNetworkMonitoring() error {
	if !*networkEnabled {
		return nil
	}

	iface, err := getDefaultInterface()
	if err != nil {
		log.Printf("Error determining default network interface: %v", err)
		return fmt.Errorf("failed to determine default network interface: %v", err)
	}

	trafficMonitor, err = stats.NewTrafficMonitor(iface)
	if err != nil {
		log.Printf("Error initializing traffic monitor for interface %s: %v", iface, err)
		return fmt.Errorf("failed to initialize traffic monitor for interface %s: %v", iface, err)
	}

	log.Printf("Network monitoring initialized for interface %s", iface)
	return nil
}

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	log.Printf("Starting v2ray-stat application %s, with core: %s", constant.Version, cfg.CoreType)

	// Инициализация базы данных и логов
	memDB, accessLog, bannedLog, offset, bannedOffset, err := initDatabase(&cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer memDB.Close()
	defer accessLog.Close()
	defer bannedLog.Close()

	// Initialize network monitoring
	if err := initNetworkMonitoring(); err != nil {
		log.Printf("Failed to initialize network monitoring: %v", err)
	}

	// Setup context and signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start tasks
	wg.Add(1)
	go startAPIServer(ctx, memDB, &cfg, &wg)
	monitorSubscriptionsAndSync(ctx, memDB, &cfg, &wg)
	monitorUsersAndLogs(ctx, memDB, accessLog, offset, &cfg, &wg)
	monitor.MonitorBannedLogRoutine(ctx, bannedLog, bannedOffset, &cfg, &wg)
	monitor.MonitorExcessIPs(ctx, memDB, &cfg, &wg)
	stats.MonitorNetworkRoutine(ctx, networkEnabled, trafficMonitor, &wg)
	stats.MonitorStats(ctx, statsEnabled, &cfg, &wg)
	stats.MonitorDailyReport(ctx, memDB, &cfg, &wg)

	// Wait for termination signal
	<-sigChan
	log.Println("Received termination signal, saving data")
	cancel()

	// Synchronize database
	if err := db.SyncToFileDB(memDB, &cfg); err != nil {
		log.Printf("Error synchronizing data to fileDB: %v", err)
	} else {
		log.Println("Data successfully saved to database file")
	}

	wg.Wait()
	log.Println("Program completed")
}

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
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"xcore/api"
	"xcore/config"
	"xcore/stats"
	"xcore/telegram"

	_ "github.com/mattn/go-sqlite3"
	statsSingbox "github.com/v2ray/v2ray-core/app/stats/command"
	statsXray "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	version             string
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
	luaMutex            sync.Mutex
	trafficMonitor      *stats.TrafficMonitor
)

var (
	accessLogRegex  = regexp.MustCompile(`from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`)
	luaRegex        = regexp.MustCompile(`\["([a-f0-9-]+)"\] = (true|false)`)
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
	bannedLogRegex  = regexp.MustCompile(`(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(BAN|UNBAN)\s+\[Email\] = (\S+)\s+\[IP\] = (\S+)(?:\s+banned for (\d+) seconds\.)?`)
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

func extractData() string {
	dirPath := "/var/www/"
	files, err := os.ReadDir(dirPath)
	if err != nil {
		log.Printf("Error reading directory %s: %v", dirPath, err)
	}

	for _, file := range files {
		if file.IsDir() {
			dirName := file.Name()
			if len(dirName) == 30 {
				return dirName
			}
		}
	}

	log.Printf("No directory with a 30-character name found in %s", dirPath)
	return ""
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		PRAGMA cache_size = 10000;
		PRAGMA journal_mode = MEMORY;
	`)
	if err != nil {
		return fmt.Errorf("error setting PRAGMA: %v", err)
	}

	query := `
	CREATE TABLE IF NOT EXISTS clients_stats (
	    email TEXT PRIMARY KEY,
	    uuid TEXT,
	    status TEXT,
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
	);`

	_, err = db.Exec(query)
	if err != nil {
		return fmt.Errorf("error executing SQL query: %v", err)
	}
	log.Printf("Database initialized successfully")
	return nil
}

func backupDB(srcDB, memDB *sql.DB, cfg *config.Config) error {
	srcConn, err := srcDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("error obtaining connection to source database: %v", err)
	}
	defer srcConn.Close()

	destConn, err := memDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("error obtaining connection to target database: %v", err)
	}
	defer destConn.Close()

	_, err = destConn.ExecContext(context.Background(), fmt.Sprintf("ATTACH DATABASE '%s' AS src_db", cfg.DatabasePath))
	if err != nil {
		return fmt.Errorf("error attaching source database: %v", err)
	}

	_, err = destConn.ExecContext(context.Background(), `
        CREATE TABLE IF NOT EXISTS clients_stats (
            email TEXT PRIMARY KEY,
            uuid TEXT,
            status TEXT,
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
            sess_uplink INTEGER DEFAULT 0,
            sess_downlink INTEGER DEFAULT 0,
            uplink INTEGER DEFAULT 0,
            downlink INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS dns_stats (
            email TEXT NOT NULL,
            count INTEGER DEFAULT 1,
            domain TEXT NOT NULL,
            PRIMARY KEY (email, domain)
        );
    `)

	if err != nil {
		return fmt.Errorf("error creating tables in memDB: %v", err)
	}

	for _, table := range []string{"clients_stats", "traffic_stats", "dns_stats"} {
		_, err = destConn.ExecContext(context.Background(), fmt.Sprintf(`
            INSERT OR REPLACE INTO %s SELECT * FROM src_db.%s;
        `, table, table))
		if err != nil {
			return fmt.Errorf("error copying data for table %s: %v", table, err)
		}
	}

	_, err = destConn.ExecContext(context.Background(), "DETACH DATABASE src_db;")
	if err != nil {
		return fmt.Errorf("error detaching source database: %v", err)
	}

	return nil
}

func extractUsersXrayServer(cfg *config.Config) []config.Client {
	configPath := cfg.CoreDir + "config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
		return nil
	}

	var cfgXray config.ConfigXray
	if err := json.Unmarshal(data, &cfgXray); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		return nil
	}

	var clients []config.Client
	for _, inbound := range cfgXray.Inbounds {
		if inbound.Tag == "vless-in" {
			clients = append(clients, inbound.Settings.Clients...)
		}
	}

	return clients
}

func extractUsersSingboxServer(cfg *config.Config) []config.Client {
	configPath := cfg.CoreDir + "config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Ошибка чтения config.json для Singbox: %v", err)
		return nil
	}

	var cfgSingbox config.ConfigSingBox
	if err := json.Unmarshal(data, &cfgSingbox); err != nil {
		log.Printf("Ошибка парсинга JSON для Singbox: %v", err)
		return nil
	}

	var clients []config.Client
	for _, inbound := range cfgSingbox.Inbounds {
		if inbound.Tag == "vless-in" || inbound.Tag == "trojan-in" {
			for _, user := range inbound.Users {
				client := config.Client{
					Email: user.Name,
				}
				if inbound.Type == "vless" {
					client.ID = user.UUID
				} else if inbound.Type == "trojan" {
					client.Password = user.Password
					client.ID = user.Password // Используем Password как ID для Trojan
				}
				clients = append(clients, client)
			}
		}
	}

	return clients
}

func getFileCreationTime(email string) (string, error) {
	subJsonPath := extractData()
	if subJsonPath == "" {
		return "", fmt.Errorf("failed to extract path from configuration file")
	}

	subPath := fmt.Sprintf("/var/www/%s/vless-in/%s.json", subJsonPath, email)
	if _, err := os.Stat(subPath); os.IsNotExist(err) {
		return time.Now().Format("2006-01-02-15"), nil
	}

	var stat syscall.Stat_t
	err := syscall.Stat(subPath, &stat)
	if err != nil {
		return "", err
	}

	creationTime := time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
	formattedTime := creationTime.Format("2006-01-02-15")

	return formattedTime, nil
}

func addUserToDB(memDB *sql.DB, cfg *config.Config) error {
	var clients []config.Client
	switch cfg.CoreType {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

	if len(clients) == 0 {
		log.Printf("Не найдено пользователей для добавления в БД для типа %s", cfg.CoreType)
		return nil
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()

	tx, err := memDB.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO clients_stats(email, uuid, status, enabled, created) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()

	var addedEmails []string
	for _, client := range clients {
		createdClient, err := getFileCreationTime(client.Email)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to get file creation date for client %s: %v", client.Email, err)
		}

		result, err := stmt.Exec(client.Email, client.ID, "offline", "true", createdClient)
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
		log.Printf("Users successfully added to database: %s", strings.Join(addedEmails, ", "))
	}

	return nil
}

func delUserFromDB(memDB *sql.DB, cfg *config.Config) error {
	var clients []config.Client
	switch cfg.CoreType {
	case "xray":
		clients = extractUsersXrayServer(cfg)
	case "singbox":
		clients = extractUsersSingboxServer(cfg)
	}

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
		log.Printf("Users successfully deleted from database: %s", strings.Join(deletedEmails, ", "))
	}

	return nil
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
			return nil, fmt.Errorf("ошибка выполнения gRPC-запроса Xray: %w", err)
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
			return nil, fmt.Errorf("ошибка выполнения gRPC-запроса Singbox: %w", err)
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

		if direction == "uplink" {
			uplinkValues[source] = diff
			sessUplinkValues[source] = current
		} else if direction == "downlink" {
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

		if direction == "uplink" {
			clientUplinkValues[email] = diff
			clientSessUplinkValues[email] = current
		} else if direction == "downlink" {
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

		if direction == "uplink" {
			if _, exists := clientSessUplinkValues[email]; !exists {
				clientSessUplinkValues[email] = 0
				clientUplinkValues[email] = 0
			}
		} else if direction == "downlink" {
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
			log.Fatalf("error executing transaction: %v", err)
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

func updateEnabledInDB(memDB *sql.DB, uuid string, enabled string) {
	_, err := memDB.Exec("UPDATE clients_stats SET enabled = ? WHERE uuid = ?", enabled, uuid)
	if err != nil {
		log.Printf("Error updating database: %v", err)
	}
}

func parseAndUpdate(memDB *sql.DB, file *os.File) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := luaRegex.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		uuid := matches[1]
		enabled := matches[2]
		updateEnabledInDB(memDB, uuid, enabled)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading Lua file: %v", err)
	}
}

func logExcessIPs(memDB *sql.DB, cfg *config.Config) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	logFile, err := os.OpenFile(cfg.XipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file %s: %v", cfg.XipLogFile, err)
		return fmt.Errorf("error opening log file: %v", err)
	}
	defer logFile.Close()

	currentTime := time.Now().Format("2006/01/02 15:04:05")

	rows, err := memDB.Query("SELECT email, lim_ip, ips FROM clients_stats")
	if err != nil {
		log.Printf("Error querying clients_stats: %v", err)
		return fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var email, ipAddresses string
		var ipLimit int

		err := rows.Scan(&email, &ipLimit, &ipAddresses)
		if err != nil {
			log.Printf("Error scanning row for email %s: %v", email, err)
			return fmt.Errorf("error scanning row: %v", err)
		}

		if ipLimit == 0 {
			continue
		}

		ipAddresses = strings.Trim(ipAddresses, "[]")
		ipList := strings.Split(ipAddresses, ",")

		filteredIPList := make([]string, 0, len(ipList))
		for _, ips := range ipList {
			ips = strings.TrimSpace(ips)
			if ips != "" {
				filteredIPList = append(filteredIPList, ips)
			}
		}

		if len(filteredIPList) > ipLimit {
			excessIPs := filteredIPList[ipLimit:]
			for _, ips := range excessIPs {
				logData := fmt.Sprintf("%s [LIMIT_IP] Email = %s || SRC = %s\n", currentTime, email, ips)
				_, err := logFile.WriteString(logData)
				if err != nil {
					log.Printf("Error writing to log file for email %s, IP %s: %v", email, ips, err)
					return fmt.Errorf("error writing to log file: %v", err)
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
		return fmt.Errorf("error iterating rows: %v", err)
	}

	return nil
}

type DNSStat struct {
	Email  string
	Domain string
	Count  int
}

func updateIPInDB(tx *sql.Tx, email string, ipList []string) error {
	ipStr := strings.Join(ipList, ",")
	query := `UPDATE clients_stats SET ips = ? WHERE email = ?`
	_, err := tx.Exec(query, ipStr, email)
	if err != nil {
		return fmt.Errorf("ошибка при обновлении данных: %v", err)
	}
	return nil
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
				return fmt.Errorf("ошибка при пакетном обновлении dns_stats: %v", err)
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

	if err := updateIPInDB(tx, email, validIPs); err != nil {
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

func monitorBannedLog(bannedLog *os.File, offset *int64, cfg *config.Config) {
	bannedLog.Seek(*offset, 0)
	scanner := bufio.NewScanner(bannedLog)

	for scanner.Scan() {
		line := scanner.Text()
		matches := bannedLogRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			log.Printf("Invalid line in ban log: %s", line)
			continue
		}

		timestamp := matches[1]
		action := matches[2]
		email := matches[3]
		ip := matches[4]
		banDuration := "unknown"
		if len(matches) == 6 && matches[5] != "" {
			banDuration = matches[5] + " seconds"
		}

		var message string
		if action == "BAN" {
			message = fmt.Sprintf("🚫 IP Banned\n\n"+
				" Client:   *%s*\n"+
				" IP:   *%s*\n"+
				" Time:   *%s*\n"+
				" Duration:   *%s*", email, ip, timestamp, banDuration)
		} else {
			message = fmt.Sprintf("✅ IP Unbanned\n\n"+
				" Client:   *%s*\n"+
				" IP:   *%s*\n"+
				" Time:   *%s*", email, ip, timestamp)
		}

		if cfg.TelegramBotToken != "" && cfg.TelegramChatId != "" {
			if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatId, message); err != nil {
				log.Printf("Error sending ban notification: %v", err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading ban log: %v", err)
	}

	pos, err := bannedLog.Seek(0, 1)
	if err != nil {
		log.Printf("Error retrieving ban log position: %v", err)
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
						err = updateLuaUuid(s.UUID, true, cfg)
						if err != nil {
							log.Printf("Error enabling user %s: %v", s.Email, err)
							continue
						}
						updateEnabledInDB(memDB, s.UUID, "true")
						log.Printf("User %s enabled", s.Email)
					}
				} else if s.Enabled == "true" {
					err = updateLuaUuid(s.UUID, false, cfg)
					if err != nil {
						log.Printf("Error disabling user %s: %v", s.Email, err)
					} else {
						log.Printf("User %s disabled", s.Email)
					}
					updateEnabledInDB(memDB, s.UUID, "false")
				}
			} else {
				if s.Enabled == "false" {
					err = updateLuaUuid(s.UUID, true, cfg)
					if err != nil {
						log.Printf("Error enabling user %s: %v", s.Email, err)
						continue
					}
					updateEnabledInDB(memDB, s.UUID, "true")
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
		email := r.FormValue("email")
		sub_end := r.FormValue("sub_end")
		if email == "" || sub_end == "" {
			http.Error(w, "email and sub_end are required", http.StatusBadRequest)
			return
		}

		dbMutex.Lock()
		baseDate := time.Now().UTC()
		var subEndStr string
		err := memDB.QueryRow("SELECT sub_end FROM clients_stats WHERE email = ?", email).Scan(&subEndStr)
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
		err = adjustDateOffset(memDB, email, sub_end, baseDate)
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
		_, err = fmt.Fprintf(w, "Subscription date for %s updated with sub_end %s\n", email, sub_end)
		if err != nil {
			log.Printf("Error writing response for email %s: %v", email, err)
			http.Error(w, "Error sending response", http.StatusInternalServerError)
			return
		}
	}
}

func updateLuaUuid(uuid string, enabled bool, cfg *config.Config) error {
	data, err := os.ReadFile(cfg.LuaFilePath)
	if err != nil {
		log.Printf("Error reading Lua file %s: %v", cfg.LuaFilePath, err)
		return fmt.Errorf("error reading Lua file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	updated := false

	for i, line := range lines {
		matches := luaRegex.FindStringSubmatch(line)
		if len(matches) == 3 && matches[1] == uuid {
			lines[i] = fmt.Sprintf(`  ["%s"] = %t,`, uuid, enabled)
			updated = true
			break
		}
	}

	if !updated {
		return nil
	}

	newContent := strings.Join(lines, "\n")
	err = os.WriteFile(cfg.LuaFilePath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("error writing to Lua file: %v", err)
	}

	cmd := exec.Command("systemctl", "restart", "haproxy")
	err = cmd.Run()
	if err != nil {
		log.Printf("Error restarting Haproxy: %v", err)
	} else {
		log.Printf("Haproxy successfully restarted")
	}

	return nil
}

func setEnabledHandler(memDB *sql.DB, cfg *config.Config) http.HandlerFunc {
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

		email := r.FormValue("email")
		enabledStr := r.FormValue("enabled")

		if email == "" {
			http.Error(w, "email is required", http.StatusBadRequest)
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

		var uuid string
		var err error
		err = memDB.QueryRow("SELECT uuid FROM clients_stats WHERE email = ?", email).Scan(&uuid)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User with this email not found", http.StatusNotFound)
				return
			}
			log.Printf("Error querying database: %v", err)
			http.Error(w, "Server error querying database", http.StatusInternalServerError)
			return
		}

		luaMutex.Lock()
		defer luaMutex.Unlock()

		err = updateLuaUuid(uuid, enabled, cfg)
		if err != nil {
			log.Printf("Error updating Lua file: %v", err)
			http.Error(w, "Error updating authorization file", http.StatusInternalServerError)
			return
		}

		updateEnabledInDB(memDB, uuid, enabledStr)

		log.Printf("For email %s (uuid %s), value set to %t", email, uuid, enabled)
		w.WriteHeader(http.StatusOK)
	}
}

func startAPIServer(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	server := &http.Server{
		Addr:    "127.0.0.1:" + cfg.Port,
		Handler: nil,
	}

	http.HandleFunc("/api/v1/users", api.UsersHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/stats", api.StatsHandler(memDB, &dbMutex, statsEnabled, networkEnabled, trafficMonitor, cfg.Services))
	http.HandleFunc("/api/v1/reset-traffic", api.ResetTrafficHandler(trafficMonitor))
	http.HandleFunc("/api/v1/dns_stats", api.DnsStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/add_user", api.AddUserHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/delete-user", api.DeleteUserHandler(memDB, &dbMutex, cfg))
	http.HandleFunc("/api/v1/update_lim_ip", api.UpdateIPLimitHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/delete_dns_stats", api.DeleteDNSStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/reset_traffic_stats", api.ResetTrafficStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/reset_clients_stats", api.ResetClientsStatsHandler(memDB, &dbMutex))
	http.HandleFunc("/api/v1/adjust-date", adjustDateOffsetHandler(memDB, cfg))
	http.HandleFunc("/api/v1/set-enabled", setEnabledHandler(memDB, cfg))
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

func syncToFileDB(memDB *sql.DB, cfg *config.Config) error {
	_, err := os.Stat(cfg.DatabasePath)
	fileExists := !os.IsNotExist(err)

	dbMutex.Lock()
	defer dbMutex.Unlock()

	fileDB, err := sql.Open("sqlite3", cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("error opening fileDB: %v", err)
	}
	defer fileDB.Close()

	if !fileExists {
		err = initDB(fileDB)
		if err != nil {
			return fmt.Errorf("error initializing fileDB: %v", err)
		}
	}

	tables := []string{"clients_stats", "traffic_stats", "dns_stats"}

	tx, err := fileDB.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction in fileDB: %v", err)
	}

	for _, table := range tables {
		_, err = tx.Exec(fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error clearing table %s in fileDB: %v", table, err)
		}

		rows, err := memDB.Query(fmt.Sprintf("SELECT * FROM %s", table))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error retrieving data from memDB for table %s: %v", table, err)
		}
		defer rows.Close()

		columns, err := rows.Columns()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error retrieving columns: %v", err)
		}

		placeholders := strings.Repeat("?,", len(columns)-1) + "?"
		insertQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ","), placeholders)
		stmt, err := tx.Prepare(insertQuery)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error preparing query: %v", err)
		}
		defer stmt.Close()

		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		for rows.Next() {
			if err := rows.Scan(valuePtrs...); err != nil {
				tx.Rollback()
				return fmt.Errorf("error scanning row: %v", err)
			}
			_, err = stmt.Exec(values...)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("error inserting row: %v", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
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

		if err = initDB(fileDB); err != nil {
			log.Printf("Error initializing database: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to initialize database: %v", err)
		}

		if err = backupDB(fileDB, memDB, cfg); err != nil {
			log.Printf("Error copying data to memory: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to copy data to memory: %v", err)
		}
	} else {
		if err = initDB(memDB); err != nil {
			log.Printf("Error initializing in-memory database: %v", err)
			memDB.Close()
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to initialize in-memory database: %v", err)
		}
	}

	accessLog, err = os.Open(cfg.AccessLogPath)
	if err != nil {
		log.Printf("Error opening access.log: %v", err)
		memDB.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open access.log: %v", err)
	}

	bannedLog, err = os.Open(cfg.BannedLogFile)
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

// Запуск задачи логирования избыточных IP
func monitorExcessIPs(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := logExcessIPs(memDB, cfg); err != nil {
					log.Printf("Error logging IPs: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
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
				checkExpiredSubscriptions(memDB, cfg)

				luaConf, err := os.Open(cfg.LuaFilePath)
				if err != nil {
					log.Printf("Error opening Lua file: %v", err)
				} else {
					parseAndUpdate(memDB, luaConf)
					luaConf.Close()
				}

				if err := syncToFileDB(memDB, cfg); err != nil {
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
func monitorUsersAndLogs(ctx context.Context, memDB *sql.DB, accessLog, bannedLog *os.File, offset, bannedOffset *int64, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := addUserToDB(memDB, cfg); err != nil {
					log.Printf("Ошибка добавления пользователей: %v", err)
				}
				if err := delUserFromDB(memDB, cfg); err != nil {
					log.Printf("Ошибка удаления пользователей: %v", err)
				}

				apiData, err := getApiResponse(cfg)
				if err != nil {
					log.Printf("Error retrieving API data: %v", err)
				} else {
					updateProxyStats(memDB, apiData)
					updateClientStats(memDB, apiData)
				}
				readNewLines(memDB, accessLog, offset, cfg)
				monitorBannedLog(bannedLog, bannedOffset, cfg)
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

// Запуск мониторинга сети
func monitorNetwork(ctx context.Context, wg *sync.WaitGroup) {
	if !*networkEnabled || trafficMonitor == nil {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := trafficMonitor.UpdateStats(); err != nil {
					log.Printf("Error updating network stats for interface %s: %v", trafficMonitor.Iface, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func monitorStats(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) {
	if !*statsEnabled {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if cfg.TelegramBotToken != "" && cfg.TelegramChatId != "" {
					stats.CheckServiceStatus(cfg.Services, cfg.TelegramBotToken, cfg.TelegramChatId)
					stats.CheckDiskUsage(cfg.TelegramBotToken, cfg.TelegramChatId, cfg.DiskThreshold, cfg.MemoryAverageInterval)
					stats.CheckMemoryUsage(cfg.TelegramBotToken, cfg.TelegramChatId, cfg.MemoryThreshold, cfg.MemoryAverageInterval)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	log.Printf("Starting xCore application, with core: %s, version %s", cfg.CoreType, version)

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
	monitorExcessIPs(ctx, memDB, &cfg, &wg)
	monitorSubscriptionsAndSync(ctx, memDB, &cfg, &wg)
	monitorUsersAndLogs(ctx, memDB, accessLog, bannedLog, offset, bannedOffset, &cfg, &wg)
	monitorNetwork(ctx, &wg)
	monitorStats(ctx, &cfg, &wg)

	// Wait for termination signal
	<-sigChan
	log.Println("Received termination signal, saving data")
	cancel()

	// Synchronize database
	if err := syncToFileDB(memDB, &cfg); err != nil {
		log.Printf("Error synchronizing data to fileDB: %v", err)
	} else {
		log.Println("Data successfully saved to database file")
	}

	wg.Wait()
	log.Println("Program completed")
}

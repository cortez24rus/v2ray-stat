// Copyright (c) 2025 xCore Authors
// This file is part of xCore.
// xCore is licensed under the xCore Software License. See the LICENSE file for details.

package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"xcore/license"

	_ "github.com/mattn/go-sqlite3"
	stats "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Program version, set during build
var Version string

type Config struct {
	DatabasePath     string
	DirXray          string
	LUAFilePath      string
	XIPLLogFile      string
	BannedLogFile    string
	IP_TTL           time.Duration
	Port             string
	TelegramBotToken string
	TelegramChatID   string
}

var defaultConfig = Config{
	LUAFilePath:      "/etc/haproxy/.auth.lua",
	DatabasePath:     "/usr/local/xcore/data.db",
	DirXray:          "/usr/local/etc/xray/",
	XIPLLogFile:      "/var/log/xcore.log",
	BannedLogFile:    "/var/log/xcore-banned.log",
	Port:             "9952",
	IP_TTL:           66 * time.Second,
	TelegramBotToken: "",
	TelegramChatID:   "",
}

var config Config
var (
	dnsEnabled          = flag.Bool("dns", false, "Enable DNS statistics collection")
	uniqueEntries       = make(map[string]map[string]time.Time)
	uniqueEntriesMutex  sync.Mutex
	renewNotifiedUsers  = make(map[string]bool)
	dbMutex             sync.Mutex
	previousStats       string
	clientPreviousStats string
	notifiedUsers       = make(map[string]bool)
	notifiedMutex       sync.Mutex
	luaMutex            sync.Mutex
)

var (
	accessLogRegex  = regexp.MustCompile(`from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`)
	luaRegex        = regexp.MustCompile(`\["([a-f0-9-]+)"\] = (true|false)`)
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
	bannedLogRegex  = regexp.MustCompile(`(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(BAN|UNBAN)\s+\[Email\] = (\S+)\s+\[IP\] = (\S+)(?:\s+banned for (\d+) seconds\.)?`)
)

// sendTelegramNotification sends a notification to a Telegram chat
func sendTelegramNotification(token, chatID, message string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?parse_mode=markdown", token)
	data := url.Values{
		"chat_id": {chatID},
		"text":    {message},
	}

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		log.Printf("Error sending Telegram notification: %v", err)
		return fmt.Errorf("error sending notification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to send Telegram notification, status: %d", resp.StatusCode)
		return fmt.Errorf("failed to send notification, status: %d", resp.StatusCode)
	}

	return nil
}

// loadConfig loads configuration from a file or uses default values
func loadConfig(configFile string) error {
	config = defaultConfig

	file, err := os.Open(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Configuration file %s not found, using default values", configFile)
			return nil
		}
		return fmt.Errorf("error opening configuration file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	configMap := make(map[string]string)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: invalid line in configuration: %s", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		configMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading configuration file: %v", err)
	}

	if val, ok := configMap["DatabasePath"]; ok && val != "" {
		config.DatabasePath = val
	}
	if val, ok := configMap["DirXray"]; ok && val != "" {
		config.DirXray = val
	}
	if val, ok := configMap["LUAFilePath"]; ok && val != "" {
		config.LUAFilePath = val
	}
	if val, ok := configMap["XIPLLogFile"]; ok && val != "" {
		config.XIPLLogFile = val
	}
	if val, ok := configMap["BannedLogFile"]; ok && val != "" {
		config.BannedLogFile = val
	}
	if val, ok := configMap["Port"]; ok && val != "" {
		portNum, err := strconv.Atoi(val)
		if err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid port: %s", val)
		}
		config.Port = val
	}
	if val, ok := configMap["TelegramBotToken"]; ok && val != "" {
		config.TelegramBotToken = val
	}
	if val, ok := configMap["TelegramChatID"]; ok && val != "" {
		config.TelegramChatID = val
	}

	return nil
}

type Client struct {
	Email string `json:"email"`
	ID    string `json:"id"`
}

type Inbound struct {
	Tag      string `json:"tag"`
	Settings struct {
		Clients []Client `json:"clients"`
	} `json:"settings"`
}

type ConfigXray struct {
	Inbounds []Inbound `json:"inbounds"`
}

type Stat struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ApiResponse struct {
	Stat []Stat `json:"stat"`
}

// extractData extracts the path from the HAProxy configuration file
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

// initDB initializes the database with the specified tables
func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		PRAGMA cache_size = 10000;  -- Increases cache (10000 pages ≈ 40 MB RAM)
		PRAGMA journal_mode = MEMORY; -- Stores transaction journal in RAM
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

// backupDB performs a backup of data from one database to another
func backupDB(srcDB, memDB *sql.DB) error {
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

	_, err = destConn.ExecContext(context.Background(), fmt.Sprintf("ATTACH DATABASE '%s' AS src_db", config.DatabasePath))
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

// extractUsersXrayServer extracts the list of users from the Xray configuration
func extractUsersXrayServer() []Client {
	configPath := config.DirXray + "config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Error reading config.json: %v", err)
		return nil
	}

	var config ConfigXray
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		return nil
	}

	var clients []Client
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "vless_raw" {
			clients = append(clients, inbound.Settings.Clients...)
		}
	}

	return clients
}

// getFileCreationTime returns the creation time of a file in the specified format
func getFileCreationTime(email string) (string, error) {
	subJsonPath := extractData()
	if subJsonPath == "" {
		return "", fmt.Errorf("failed to extract path from configuration file")
	}

	subPath := fmt.Sprintf("/var/www/%s/vless_raw/%s.json", subJsonPath, email)
	var stat syscall.Stat_t
	err := syscall.Stat(subPath, &stat)
	if err != nil {
		return "", err
	}

	creationTime := time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
	formattedTime := creationTime.Format("2006-01-02-15")

	return formattedTime, nil
}

// addUserToDB adds users to the database
func addUserToDB(memDB *sql.DB, clients []Client) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	tx, err := memDB.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO clients_stats(email, uuid, status, enabled, created) VALUES (?, ?, ?, ?, ?, ?)")
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

// delUserFromDB deletes users from the database that are not in the provided list
func delUserFromDB(memDB *sql.DB, clients []Client) error {
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

// getApiResponse retrieves statistics via the Xray API
func getApiResponse() (*ApiResponse, error) {
	clientConn, err := grpc.NewClient("127.0.0.1:9953", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("error connecting to gRPC server: %w", err)
	}
	defer clientConn.Close()

	client := stats.NewStatsServiceClient(clientConn)

	req := &stats.QueryStatsRequest{
		Pattern: "",
		Reset_:  false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.QueryStats(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("error executing gRPC request: %w", err)
	}

	apiResponse := &ApiResponse{
		Stat: make([]Stat, len(resp.GetStat())),
	}
	for i, stat := range resp.GetStat() {
		apiResponse.Stat[i] = Stat{
			Name:  stat.GetName(),
			Value: strconv.FormatInt(stat.GetValue(), 10),
		}
	}

	return apiResponse, nil
}

// extractProxyTraffic extracts proxy traffic statistics
func extractProxyTraffic(apiData *ApiResponse) []string {
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

// extractUserTraffic extracts user traffic statistics
func extractUserTraffic(apiData *ApiResponse) []string {
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

// splitAndCleanName splits and cleans the statistics name
func splitAndCleanName(name string) []string {
	parts := strings.Split(name, ">>>")
	if len(parts) == 4 {
		return []string{parts[1], parts[3]}
	}
	return nil
}

// updateProxyStats updates proxy statistics in the database
func updateProxyStats(memDB *sql.DB, apiData *ApiResponse) {
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

// updateClientStats updates client statistics in the database
func updateClientStats(memDB *sql.DB, apiData *ApiResponse) {
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

// stringToInt converts a string to an integer
func stringToInt(s string) int {
	result, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("Error converting string '%s' to integer: %v", s, err)
		return 0
	}
	return result
}

// updateEnabledInDB updates the enabled status for a user in the database
func updateEnabledInDB(memDB *sql.DB, uuid string, enabled string) {
	_, err := memDB.Exec("UPDATE clients_stats SET enabled = ? WHERE uuid = ?", enabled, uuid)
	if err != nil {
		log.Printf("Error updating database: %v", err)
	}
}

// parseAndUpdate parses a Lua file and updates the enabled status in the database
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

// logExcessIPs logs IP address limit exceedances
func logExcessIPs(memDB *sql.DB) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	logFile, err := os.OpenFile(config.XIPLLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file %s: %v", config.XIPLLogFile, err)
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

// updateIPInDB обновляет список IP-адресов для пользователя в базе данных
func updateIPInDB(tx *sql.Tx, email string, ipList []string) error {
	ipStr := strings.Join(ipList, ",")
	query := `UPDATE clients_stats SET ips = ? WHERE email = ?`
	_, err := tx.Exec(query, ipStr, email)
	if err != nil {
		return fmt.Errorf("ошибка при обновлении данных: %v", err)
	}
	return nil
}

// upsertDNSRecordsBatch выполняет пакетное обновление записей DNS-статистики
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

// processLogLine processes a log line and updates data
func processLogLine(tx *sql.Tx, line string, dnsStats map[string]map[string]int) {
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
		if time.Since(timestamp) <= config.IP_TTL {
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

// readNewLines reads new lines from the log and updates the database
func readNewLines(memDB *sql.DB, file *os.File, offset *int64) {
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
		processLogLine(tx, scanner.Text(), dnsStats)
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

// monitorBannedLog monitors the ban log and sends Telegram notifications
func monitorBannedLog(bannedLog *os.File, offset *int64) {
	bannedLog.Seek(*offset, 0)
	scanner := bufio.NewScanner(bannedLog)

	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Error retrieving hostname: %v", err)
		hostname = "unknown"
	}

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
				" Hostname:   *%s*\n"+
				" Client:   *%s*\n"+
				" IP:   *%s*\n"+
				" Time:   *%s*\n"+
				" Duration:   *%s*", hostname, email, ip, timestamp, banDuration)
		} else {
			message = fmt.Sprintf("✅ IP Unbanned\n\n"+
				" Hostname:   *%s*\n"+
				" Client:   *%s*\n"+
				" IP:   *%s*\n"+
				" Time:   *%s*", hostname, email, ip, timestamp)
		}

		if config.TelegramBotToken != "" && config.TelegramChatID != "" {
			if err := sendTelegramNotification(config.TelegramBotToken, config.TelegramChatID, message); err != nil {
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

// formatDate formats a date string with timezone information
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

// checkExpiredSubscriptions checks for expired subscriptions and updates status
func checkExpiredSubscriptions(memDB *sql.DB, botToken, chatID string) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Error retrieving hostname: %v", err)
		hostname = "unknown"
	}

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
				canSendNotifications := botToken != "" && chatID != ""

				notifiedMutex.Lock()
				if canSendNotifications && !notifiedUsers[s.Email] {
					formattedDate := formatDate(s.SubEnd)
					message := fmt.Sprintf("❌ Subscription expired\n\n"+
						"Hostname:   *%s*\n"+
						"Client:   *%s*\n"+
						"Expiration date:   *%s*", hostname, s.Email, formattedDate)
					if err := sendTelegramNotification(botToken, chatID, message); err == nil {
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
							"Hostname:   *%s*\n"+
							"Client:   *%s days*\n"+
							"Renewed for:   *%d*", hostname, s.Email, s.Renew)
						if err := sendTelegramNotification(botToken, chatID, message); err == nil {
							renewNotifiedUsers[s.Email] = true
						}
					}

					notifiedMutex.Lock()
					notifiedUsers[s.Email] = false
					renewNotifiedUsers[s.Email] = false
					notifiedMutex.Unlock()

					if s.Enabled == "false" {
						err = updateLuaUuid(s.UUID, true)
						if err != nil {
							log.Printf("Error enabling user %s: %v", s.Email, err)
							continue
						}
						updateEnabledInDB(memDB, s.UUID, "true")
						log.Printf("User %s enabled", s.Email)
					}
				} else if s.Enabled == "true" {
					err = updateLuaUuid(s.UUID, false)
					if err != nil {
						log.Printf("Error disabling user %s: %v", s.Email, err)
					} else {
						log.Printf("User %s disabled", s.Email)
					}
					updateEnabledInDB(memDB, s.UUID, "false")
				}
			} else {
				if s.Enabled == "false" {
					err = updateLuaUuid(s.UUID, true)
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

// User represents the structure of a user with email and enabled status
type User struct {
	Email   string `json:"email"`
	Enabled string `json:"enabled"`
	Sub_end string `json:"sub_end"`
	Lim_ip  string `json:"lim_ip"`
	Renew   int    `json:"renew"`
}

// usersHandler returns a list of users in JSON format
func usersHandler(memDB *sql.DB) http.HandlerFunc {
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

// contains is a helper function to check if a column is traffic-related
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// statsHandler returns server and client statistics
func statsHandler(memDB *sql.DB) http.HandlerFunc {
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

		stats := " 🌐 Server Statistics:\n============================\n"

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

		trafficColsServer := []string{"Sess Up", "Sess.Real Down", "Upload", "Download"}

		serverTable, err := formatTable(rows, trafficColsServer)
		if err != nil {
			log.Printf("Error formatting table: %v", err)
			http.Error(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		stats += serverTable

		stats += "\n 📊 Client Statistics:\n============================\n"

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
                lim_ip AS "Lim_ip",
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
		stats += clientTable

		fmt.Fprintln(w, stats)
	}
}

// dnsStatsHandler returns DNS query statistics
func dnsStatsHandler(memDB *sql.DB) http.HandlerFunc {
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

		stats := " 📊 DNS Query Statistics:\n============================\n"
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

// updateIPLimitHandler updates the IP limit for a user
func updateIPLimitHandler(memDB *sql.DB) http.HandlerFunc {
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

// deleteDNSStatsHandler deletes DNS statistics
func deleteDNSStatsHandler(memDB *sql.DB) http.HandlerFunc {
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

// resetTrafficStatsHandler resets uplink and downlink for all sources in traffic_stats
func resetTrafficStatsHandler(memDB *sql.DB) http.HandlerFunc {
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

// resetClientsStatsHandler resets uplink and downlink for all sources in clients_stats
func resetClientsStatsHandler(memDB *sql.DB) http.HandlerFunc {
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

// parseAndAdjustDate parses a date offset and adjusts the date
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

// adjustDateOffset adjusts the subscription end date for a user
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

// adjustDateOffsetHandler adjusts the subscription end date
func adjustDateOffsetHandler(memDB *sql.DB) http.HandlerFunc {
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
			checkExpiredSubscriptions(memDB, config.TelegramBotToken, config.TelegramChatID)
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

// updateLuaUuid updates the UUID status in the Lua file
func updateLuaUuid(uuid string, enabled bool) error {
	data, err := os.ReadFile(config.LUAFilePath)
	if err != nil {
		log.Printf("Error reading Lua file %s: %v", config.LUAFilePath, err)
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
	err = os.WriteFile(config.LUAFilePath, []byte(newContent), 0644)
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

// setEnabledHandler sets the enabled status for a user
func setEnabledHandler(memDB *sql.DB) http.HandlerFunc {
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

		err = updateLuaUuid(uuid, enabled)
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

// updateRenewHandler updates the renew field for a user via HTTP request
func updateRenewHandler(memDB *sql.DB) http.HandlerFunc {
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

// startAPIServer starts the HTTP server with graceful shutdown
func startAPIServer(ctx context.Context, memDB *sql.DB, wg *sync.WaitGroup) {
	server := &http.Server{
		Addr:    "127.0.0.1:" + config.Port,
		Handler: nil,
	}

	http.HandleFunc("/api/v1/users", usersHandler(memDB))
	http.HandleFunc("/api/v1/stats", statsHandler(memDB))
	http.HandleFunc("/api/v1/dns_stats", dnsStatsHandler(memDB))
	http.HandleFunc("/api/v1/update_lim_ip", updateIPLimitHandler(memDB))
	http.HandleFunc("/api/v1/delete_dns_stats", deleteDNSStatsHandler(memDB))
	http.HandleFunc("/api/v1/reset_traffic_stats", resetTrafficStatsHandler(memDB))
	http.HandleFunc("/api/v1/reset_clients_stats", resetClientsStatsHandler(memDB))
	http.HandleFunc("/api/v1/adjust-date", adjustDateOffsetHandler(memDB))
	http.HandleFunc("/api/v1/set-enabled", setEnabledHandler(memDB))
	http.HandleFunc("/api/v1/update_renew", updateRenewHandler(memDB))

	go func() {
		log.Printf("API server starting on 127.0.0.1:%s...", config.Port)
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

// syncToFileDB synchronizes data from memory to the file database
func syncToFileDB(memDB *sql.DB) error {
	_, err := os.Stat(config.DatabasePath)
	fileExists := !os.IsNotExist(err)

	dbMutex.Lock()
	defer dbMutex.Unlock()

	fileDB, err := sql.Open("sqlite3", config.DatabasePath)
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

// main is the entry point of the program
func main() {
	license.VerifyLicense()

	flag.Parse()

	log.Printf("Starting xCore application, version %s", Version)
	if err := loadConfig(".env"); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	_, err := os.Stat(config.DatabasePath)
	fileExists := !os.IsNotExist(err)

	memDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal("Error creating in-memory database:", err)
	}
	defer memDB.Close()

	if fileExists {
		fileDB, err := sql.Open("sqlite3", config.DatabasePath)
		if err != nil {
			log.Fatal("Error opening database:", err)
		}
		defer fileDB.Close()

		err = initDB(fileDB)
		if err != nil {
			log.Fatal("Error initializing database:", err)
		}

		err = backupDB(fileDB, memDB)
		if err != nil {
			log.Fatal("Error copying data to memory:", err)
		}
	} else {
		err = initDB(memDB)
		if err != nil {
			log.Fatal("Error initializing in-memory database:", err)
		}
	}

	// Очищаем содержимое файла перед чтением
	//	err = os.Truncate(config.DirXray+"access.log", 0)
	//	if err != nil {
	//		fmt.Println("Ошибка очистки файла:", err)
	//		return
	//	}

	// Очищаем содержимое файла перед чтением
	//	err = os.Truncate(config.BannedLogFile, 0)
	//	if err != nil {
	//		fmt.Println("Ошибка очистки файла:", err)
	//		return
	//	}

	accessLog, err := os.Open(config.DirXray + "access.log")
	if err != nil {
		log.Fatalf("Error opening access.log: %v", err)
	}
	defer accessLog.Close()

	bannedLog, err := os.Open(config.BannedLogFile)
	if err != nil {
		log.Fatalf("Error opening ban log file: %v", err)
	}
	defer bannedLog.Close()

	var offset int64
	accessLog.Seek(0, 2)
	offset, err = accessLog.Seek(0, 1)
	if err != nil {
		log.Fatalf("Error getting log file position: %v", err)
	}

	var bannedOffset int64
	bannedLog.Seek(0, 2)
	bannedOffset, err = bannedLog.Seek(0, 1)
	if err != nil {
		log.Fatalf("Error getting ban log file position: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	wg.Add(1)
	go startAPIServer(ctx, memDB, &wg)

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err := logExcessIPs(memDB)
				if err != nil {
					log.Printf("Error logging IPs: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkExpiredSubscriptions(memDB, config.TelegramBotToken, config.TelegramChatID)

				luaConf, err := os.Open(config.LUAFilePath)
				if err != nil {
					log.Printf("Error opening Lua file: %v", err)
				} else {
					parseAndUpdate(memDB, luaConf)
					luaConf.Close()
				}

				if err := syncToFileDB(memDB); err != nil {
					log.Printf("Error synchronizing: %v", err)
				} else {
					log.Println("Database synchronized successfully")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				clients := extractUsersXrayServer()
				if err := addUserToDB(memDB, clients); err != nil {
					log.Printf("Error adding user: %v", err)
				}
				if err := delUserFromDB(memDB, clients); err != nil {
					log.Printf("Error deleting users: %v", err)
				}

				apiData, err := getApiResponse()
				if err != nil {
					log.Printf("Error retrieving API data: %v", err)
				} else {
					updateProxyStats(memDB, apiData)
					updateClientStats(memDB, apiData)
				}
				readNewLines(memDB, accessLog, &offset)
				monitorBannedLog(bannedLog, &bannedOffset)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-sigChan
	log.Println("Received termination signal, saving data")
	cancel()

	if err := syncToFileDB(memDB); err != nil {
		log.Printf("Error synchronizing data to fileDB: %v", err)
	} else {
		log.Println("Data successfully saved to database file")
	}

	wg.Wait()
	log.Println("Program completed")
}

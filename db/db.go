package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"v2ray-stat/config"

	_ "github.com/mattn/go-sqlite3"
)

var (
	dbMutex sync.Mutex
)

func InitDB(db *sql.DB) error {
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

func BackupDB(srcDB, memDB *sql.DB, cfg *config.Config) error {
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

func getFileCreationTime(email string) (string, error) {
	subJsonPath := extractData()
	if subJsonPath == "" {
		return "", fmt.Errorf("failed to extract path from configuration file")
	}

	subPath := fmt.Sprintf("/var/www/%s/vless_in/%s.json", subJsonPath, email)
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

func DelUserFromDB(memDB *sql.DB, cfg *config.Config) error {
	var clients []config.XrayClient
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
		err = InitDB(fileDB)
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

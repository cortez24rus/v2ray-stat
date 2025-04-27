// Copyright (c) 2025 xCore Authors
// This file is part of xCore.
// xCore is licensed under the xCore Software License. See the LICENSE file for details.
// e
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
)

type Config struct {
	DatabasePath string
	DirXray      string
	LUAFilePath  string
	XIPLLogFile  string
	IP_TTL       time.Duration
	Port         string
}

var defaultConfig = Config{
	LUAFilePath:  "/etc/haproxy/.auth.lua",
	DatabasePath: "/usr/local/xcore/data.db",
	DirXray:      "/usr/local/etc/xray/",
	XIPLLogFile:  "/var/log/xipl.log",
	Port:         "9952",
	IP_TTL:       66 * time.Second,
}

var config Config
var (
	dnsEnabled          = flag.Bool("dns", false, "Enable DNS statistics collection")
	uniqueEntries       = make(map[string]map[string]time.Time)
	uniqueEntriesMutex  sync.Mutex
	dbMutex             sync.Mutex
	previousStats       string
	clientPreviousStats string
	notifiedUsers       = make(map[string]bool)
	notifiedMutex       sync.Mutex
	luaMutex            sync.Mutex
)

// Глобальные регулярные выражения
var (
	accessLogRegex  = regexp.MustCompile(`from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`)
	luaRegex        = regexp.MustCompile(`\["([a-f0-9-]+)"\] = (true|false)`)
	dateOffsetRegex = regexp.MustCompile(`^([+-]?)(\d+)(?::(\d+))?$`)
)

// loadConfig загружает конфигурацию из файла или использует значения по умолчанию
func loadConfig(configFile string) error {
	config = defaultConfig // Устанавливаем значения по умолчанию

	file, err := os.Open(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Конфигурационный файл %s не найден, используются значения по умолчанию", configFile)
			return nil
		}
		return fmt.Errorf("ошибка открытия конфигурационного файла: %v", err)
	}
	defer file.Close()

	// Парсим файл построчно
	scanner := bufio.NewScanner(file)
	configMap := make(map[string]string)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Пропускаем пустые строки и комментарии
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Предупреждение: некорректная строка в конфигурации: %s", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		configMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения конфигурационного файла: %v", err)
	}

	// Обновляем конфигурацию, если значения указаны
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
	if val, ok := configMap["Port"]; ok && val != "" {
		portNum, err := strconv.Atoi(val)
		if err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("некорректный порт: %s", val)
		}
		config.Port = val
	}

	return nil
}

type Client struct {
	Email string `json:"email"`
	Level int    `json:"level"`
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
	Value int    `json:"value"`
}

type ApiResponse struct {
	Stat []Stat `json:"stat"`
}

// extractData извлекает путь из конфигурационного файла HAProxy
func extractData() string {
	dirPath := "/var/www/"
	files, err := os.ReadDir(dirPath)
	if err != nil {
		log.Printf("Ошибка при чтении директории %s: %v", dirPath, err)
	}

	for _, file := range files {
		if file.IsDir() {
			dirName := file.Name()
			if len(dirName) == 30 {

				return dirName
			}
		}
	}

	log.Printf("Не найдено директории с именем из 30 символов %s", dirPath)
	return ""
}

// initDB инициализирует базу данных с заданными таблицами
func initDB(db *sql.DB) error {
	// Установка PRAGMA-настроек для оптимизации
	_, err := db.Exec(`
		PRAGMA cache_size = 10000;  -- Увеличивает кэш (10000 страниц ≈ 40 MB RAM)
		PRAGMA journal_mode = MEMORY; -- Хранит журнал транзакций в RAM
	`)
	if err != nil {
		return fmt.Errorf("ошибка установки PRAGMA: %v", err)
	}

	// SQL-запрос для создания таблиц
	query := `
	CREATE TABLE IF NOT EXISTS clients_stats (
	    email TEXT PRIMARY KEY,
	    level INTEGER,
	    uuid TEXT,
	    status TEXT,
	    enabled TEXT,
	    created TEXT,
	    sub_end TEXT DEFAULT '',
	    renew INTEGER DEFAULT 0,
	    lim_ip INTEGER DEFAULT 10,
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
	);`

	// Выполнение запроса
	_, err = db.Exec(query)
	if err != nil {
		return fmt.Errorf("ошибка выполнения SQL-запроса: %v", err)
	}
	fmt.Println("Database initialized successfully")
	// Успешная инициализация базы данных
	return nil
}

// backupDB выполняет резервное копирование данных из одной базы в другую
func backupDB(srcDB, memDB *sql.DB) error {
	srcConn, err := srcDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("ошибка получения соединения с исходной базой: %v", err)
	}
	defer srcConn.Close()

	destConn, err := memDB.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("ошибка получения соединения с целевой базой: %v", err)
	}
	defer destConn.Close()

	// Присоединяем исходную базу как 'src_db'
	_, err = destConn.ExecContext(context.Background(), fmt.Sprintf("ATTACH DATABASE '%s' AS src_db", config.DatabasePath))
	if err != nil {
		return fmt.Errorf("ошибка при подключении исходной базы: %v", err)
	}

	// Создаем таблицы в memDB
	_, err = destConn.ExecContext(context.Background(), `
        CREATE TABLE IF NOT EXISTS clients_stats (
            email TEXT PRIMARY KEY,
            level INTEGER,
            uuid TEXT,
            status TEXT,
            enabled TEXT,
            created TEXT,
            sub_end TEXT DEFAULT '',
			renew INTEGER DEFAULT 0,
            lim_ip INTEGER DEFAULT 10,
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
		return fmt.Errorf("ошибка при создании таблиц в memDB: %v", err)
	}

	// Копируем данные из src_db в memDB
	for _, table := range []string{"clients_stats", "traffic_stats", "dns_stats"} {
		_, err = destConn.ExecContext(context.Background(), fmt.Sprintf(`
            INSERT OR REPLACE INTO %s SELECT * FROM src_db.%s;
        `, table, table))
		if err != nil {
			return fmt.Errorf("ошибка при копировании данных для таблицы %s: %v", table, err)
		}
	}

	// Отключаем исходную базу
	_, err = destConn.ExecContext(context.Background(), "DETACH DATABASE src_db;")
	if err != nil {
		return fmt.Errorf("ошибка при отключении исходной базы: %v", err)
	}

	return nil
}

// extractUsersXrayServer извлекает список пользователей из конфигурации Xray
func extractUsersXrayServer() []Client {
	configPath := config.DirXray + "config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Ошибка чтения config.json: %v", err)
	}

	var config ConfigXray
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("Ошибка парсинга JSON: %v", err)
	}

	var clients []Client
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "vless_raw" {
			clients = append(clients, inbound.Settings.Clients...)
		}
	}

	return clients
}

// getFileCreationTime возвращает время создания файла в заданном формате
func getFileCreationTime(email string) (string, error) {
	subJsonPath := extractData()
	if subJsonPath == "" {
		return "", fmt.Errorf("не удалось извлечь путь из конфигурационного файла")
	}

	subPath := fmt.Sprintf("/var/www/%s/vless_raw/%s.json", subJsonPath, email)
	var stat syscall.Stat_t
	err := syscall.Stat(subPath, &stat)
	if err != nil {
		return "", err
	}

	// Получаем время создания файла
	creationTime := time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))

	// Форматируем время в нужный формат: yy-mm-dd-hh
	formattedTime := creationTime.Format("2006-01-02-15")

	return formattedTime, nil
}

// addUserToDB добавляет пользователей в базу данных
func addUserToDB(memDB *sql.DB, clients []Client) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Начало транзакции
	tx, err := memDB.Begin()
	if err != nil {
		return fmt.Errorf("ошибка начала транзакции: %v", err)
	}

	// Подготовка запроса с INSERT OR IGNORE
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO clients_stats(email, level, uuid, status, enabled, created) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("ошибка подготовки запроса: %v", err)
	}
	defer stmt.Close()

	// Список добавленных email-адресов
	var addedEmails []string
	for _, client := range clients {
		// Получение даты создания
		createdClient, err := getFileCreationTime(client.Email)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("не удалось получить дату создания файла для клиента %s: %v", client.Email, err)
		}

		// Выполнение вставки
		result, err := stmt.Exec(client.Email, client.Level, client.ID, "offline", "true", createdClient)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка вставки клиента %s: %v", client.Email, err)
		}

		// Проверка, была ли запись добавлена
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка получения RowsAffected для клиента %s: %v", client.Email, err)
		}
		if rowsAffected > 0 {
			addedEmails = append(addedEmails, client.Email)
		}
	}

	// Завершение транзакции
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ошибка коммита транзакции: %v", err)
	}

	// Вывод email-адресов добавленных пользователей
	if len(addedEmails) > 0 {
		fmt.Printf("Пользователи успешно добавлены в базу данных: %s\n", strings.Join(addedEmails, ", "))
	}

	return nil
}

// delUserFromDB удаляет пользователей из базы данных, отсутствующих в списке
func delUserFromDB(memDB *sql.DB, clients []Client) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	rows, err := memDB.Query("SELECT email FROM clients_stats")
	if err != nil {
		return fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer rows.Close()

	var usersDB []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return fmt.Errorf("ошибка сканирования строки: %v", err)
		}
		usersDB = append(usersDB, email)
	}

	var Queries string
	var deletedEmails []string // Новый срез для хранения удалённых email
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
			deletedEmails = append(deletedEmails, user) // Добавляем email в список удалённых
		}
	}

	if Queries != "" {
		_, err := memDB.Exec(Queries)
		if err != nil {
			return fmt.Errorf("ошибка выполнения транзакции: %v", err)
		}
		// Выводим email-адреса удалённых пользователей
		fmt.Printf("Пользователи успешно удалены из базы данных: %s\n", strings.Join(deletedEmails, ", "))
	}

	return nil
}

// getApiResponse получает статистику через API Xray
func getApiResponse() (*ApiResponse, error) {
	cmd := exec.Command(config.DirXray+"xray", "api", "statsquery")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения команды: %w", err)
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(output, &apiResponse); err != nil {
		return nil, fmt.Errorf("ошибка парсинга JSON: %w", err)
	}

	return &apiResponse, nil
}

// extractProxyTraffic извлекает статистику трафика прокси
func extractProxyTraffic(apiData *ApiResponse) []string {
	var result []string
	for _, stat := range apiData.Stat {
		// Пропускаем user, api и blocked
		if strings.Contains(stat.Name, "user") || strings.Contains(stat.Name, "api") || strings.Contains(stat.Name, "blocked") {
			continue
		}

		parts := splitAndCleanName(stat.Name)
		if len(parts) > 0 {
			result = append(result, fmt.Sprintf("%s %d", strings.Join(parts, " "), stat.Value))
		}
	}
	return result
}

// extractUserTraffic извлекает статистику трафика пользователей
func extractUserTraffic(apiData *ApiResponse) []string {
	var result []string
	for _, stat := range apiData.Stat {
		if strings.Contains(stat.Name, "user") {
			parts := splitAndCleanName(stat.Name)
			if len(parts) > 0 {
				result = append(result, fmt.Sprintf("%s %d", strings.Join(parts, " "), stat.Value))
			}
		}
	}
	return result
}

// splitAndCleanName разделяет и очищает имя статистики
func splitAndCleanName(name string) []string {
	parts := strings.Split(name, ">>>")
	if len(parts) == 4 {
		return []string{parts[1], parts[3]}
	}
	return nil
}

// updateProxyStats обновляет статистику прокси в базе данных
func updateProxyStats(memDB *sql.DB, apiData *ApiResponse) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Получаем и фильтруем данные
	currentStats := extractProxyTraffic(apiData)

	if previousStats == "" {
		previousStats = strings.Join(currentStats, "\n")
	}

	currentValues := make(map[string]int)
	previousValues := make(map[string]int)

	// Преобразуем данные в мапу для текущих значений
	for _, line := range currentStats {
		parts := strings.Fields(line)
		// fmt.Println("Текущая строка для обработки:", line) // Добавляем вывод для каждой строки

		// Проверяем, что строка разделена на 3 части (source, direction, value)
		if len(parts) == 3 {
			currentValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
		} else {
			fmt.Println("Ошибка: некорректный формат строки:", line) // Выводим ошибку для строк с неправильным количеством частей
		}
	}

	// Преобразуем предыдущие данные в мапу
	previousLines := strings.Split(previousStats, "\n")
	for _, line := range previousLines {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			previousValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
		}
	}

	// Создаем мапы для разницы трафика
	uplinkValues := make(map[string]int)
	downlinkValues := make(map[string]int)
	sessUplinkValues := make(map[string]int)
	sessDownlinkValues := make(map[string]int)

	// Сравниваем текущие и предыдущие значения
	for key, current := range currentValues {
		previous, exists := previousValues[key]
		if !exists {
			previous = 0
		}
		diff := current - previous
		if diff < 0 {
			diff = 0
		}

		// Разделяем ключи на источник и направление
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

	// Строим запросы для вставки или обновления данных в базе
	var queries string
	for source := range uplinkValues {
		uplink := uplinkValues[source]
		downlink := downlinkValues[source]
		sessUplink := sessUplinkValues[source]
		sessDownlink := sessDownlinkValues[source]

		// Строим SQL запрос
		queries += fmt.Sprintf("INSERT OR REPLACE INTO traffic_stats (source, uplink, downlink, sess_uplink, sess_downlink) "+
			"VALUES ('%s', %d, %d, %d, %d) ON CONFLICT(source) DO UPDATE SET uplink = uplink + %d, "+
			"downlink = downlink + %d, sess_uplink = %d, sess_downlink = %d;\n", source, uplink, downlink, sessUplink, sessDownlink, uplink, downlink, sessUplink, sessDownlink)
	}

	// Если есть запросы, выполняем их
	if queries != "" {
		_, err := memDB.Exec(queries)
		if err != nil {
			log.Fatalf("ошибка выполнения транзакции: %v", err)
		}
		// fmt.Println("Данные успешно добавлены или обновлены в базе данных")
	} else {
		fmt.Println("Нет новых данных для добавления или обновления.")
	}

	// Обновляем предыдущие значения
	previousStats = strings.Join(currentStats, "\n")
}

// updateClientStats обновляет статистику клиентов в базе данных
func updateClientStats(memDB *sql.DB, apiData *ApiResponse) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Получаем и фильтруем данные
	clientCurrentStats := extractUserTraffic(apiData)

	if clientPreviousStats == "" {
		clientPreviousStats = strings.Join(clientCurrentStats, "\n")
		return
	}

	clientCurrentValues := make(map[string]int)
	clientPreviousValues := make(map[string]int)

	// Преобразуем текущие данные в мапу
	for _, line := range clientCurrentStats {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			clientCurrentValues[parts[0]+" "+parts[1]] = stringToInt(parts[2])
		} else {
			fmt.Println("Ошибка: некорректный формат строки:", line)
		}
	}

	// Преобразуем предыдущие данные в мапу
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

	// Сравниваем текущие и предыдущие значения
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

	// Обнуляем данные для отсутствующих email
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

	// Строим SQL-запросы
	var queries string
	for email := range clientUplinkValues {
		uplink := clientUplinkValues[email]
		downlink := clientDownlinkValues[email]
		sessUplink := clientSessUplinkValues[email]
		sessDownlink := clientSessDownlinkValues[email]

		// Проверяем, есть ли предыдущие данные
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

		// Определение статуса активности
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

		// SQL-запрос
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
			log.Fatalf("ошибка выполнения транзакции: %v", err)
		}
	} else {
		fmt.Println("Нет новых данных для добавления или обновления.")
	}

	clientPreviousStats = strings.Join(clientCurrentStats, "\n")
}

// stringToInt преобразует строку в целое число
func stringToInt(s string) int {
	result, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("Ошибка преобразования строки '%s' в число: %v", s, err)
		return 0
	}
	return result
}

// updateEnabledInDB обновляет статус enabled для пользователя в базе данных
func updateEnabledInDB(memDB *sql.DB, uuid string, enabled string) {
	_, err := memDB.Exec("UPDATE clients_stats SET enabled = ? WHERE uuid = ?", enabled, uuid)
	if err != nil {
		log.Printf("Ошибка обновления базы данных: %v", err)
	}
}

// parseAndUpdate парсит файл Lua и обновляет статус enabled в базе данных
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
		log.Printf("Ошибка при чтении файла Lua: %v", err)
	}
}

// logExcessIPs логирует превышение лимита IP-адресов
func logExcessIPs(memDB *sql.DB) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Открытие лог-файла
	logFile, err := os.OpenFile(config.XIPLLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	// Получение текущего времени в нужном формате
	currentTime := time.Now().Format("2006/01/02 15:04:05")

	// Запрос для получения email, lim_ip и ips из таблицы clients_stats
	rows, err := memDB.Query("SELECT email, lim_ip, ips FROM clients_stats")
	if err != nil {
		return err
	}
	defer rows.Close()

	// Обработка всех записей из таблицы
	for rows.Next() {
		var email, ipAddresses string
		var ipLimit int

		err := rows.Scan(&email, &ipLimit, &ipAddresses)
		if err != nil {
			return err
		}

		// Убираем квадратные скобки и разбиваем IP-адреса по запятой
		ipAddresses = strings.Trim(ipAddresses, "[]")
		ipList := strings.Split(ipAddresses, ",")

		// Фильтруем пустые элементы (например, если ipAddresses = "")
		filteredIPList := make([]string, 0, len(ipList)) // Выделяем срез с начальной емкостью
		for _, ips := range ipList {
			ips = strings.TrimSpace(ips)
			if ips != "" {
				filteredIPList = append(filteredIPList, ips) // Добавляем элемент
			}
		}

		if len(filteredIPList) > ipLimit {
			// Если IP-адресов больше, чем ipLimit, сохраняем избыточные в лог
			excessIPs := filteredIPList[ipLimit:]
			for _, ips := range excessIPs {
				// Формируем строку в точном формате
				logData := fmt.Sprintf("%s [LIMIT_IP] Email = %s || SRC = %s\n", currentTime, email, ips)
				_, err := logFile.WriteString(logData)
				if err != nil {
					return err
				}
			}
		}
	}

	// Проверка на ошибки после обработки строк
	if err := rows.Err(); err != nil {
		return err
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

// processLogLine обрабатывает строку лога и обновляет данные
func processLogLine(tx *sql.Tx, line string, dnsStats map[string]map[string]int) {
	matches := accessLogRegex.FindStringSubmatch(line)
	if len(matches) != 4 {
		return
	}

	email := strings.TrimSpace(matches[3])
	domain := strings.TrimSpace(matches[2])
	ips := matches[1]

	// Обновление IP-адресов
	uniqueEntriesMutex.Lock()
	if uniqueEntries[email] == nil {
		uniqueEntries[email] = make(map[string]time.Time)
	}
	uniqueEntries[email][ips] = time.Now()
	uniqueEntriesMutex.Unlock()

	validIPs := []string{}
	for ips, timestamp := range uniqueEntries[email] {
		if time.Since(timestamp) <= config.IP_TTL {
			validIPs = append(validIPs, ips)
		} else {
			delete(uniqueEntries[email], ips)
		}
	}

	if err := updateIPInDB(tx, email, validIPs); err != nil {
		log.Printf("Ошибка при обновлении IP в БД: %v", err)
	}

	// Накапливаем данные о DNS-запросах в мапе
	if *dnsEnabled {
		if dnsStats[email] == nil {
			dnsStats[email] = make(map[string]int)
		}
		dnsStats[email][domain]++
	}
}

// readNewLines читает новые строки из лога и обновляет базу данных
func readNewLines(memDB *sql.DB, file *os.File, offset *int64) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	file.Seek(*offset, 0)
	scanner := bufio.NewScanner(file)

	// Начинаем транзакцию
	tx, err := memDB.Begin()
	if err != nil {
		log.Printf("Ошибка при создании транзакции: %v", err)
		return
	}

	// Создаем мапу для накопления DNS-запросов
	dnsStats := make(map[string]map[string]int)

	// Обрабатываем строки и накапливаем данные
	for scanner.Scan() {
		processLogLine(tx, scanner.Text(), dnsStats)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Ошибка чтения файла: %v", err)
		tx.Rollback()
		return
	}

	// Выполняем пакетное обновление DNS-запросов
	if *dnsEnabled && len(dnsStats) > 0 {
		if err := upsertDNSRecordsBatch(tx, dnsStats); err != nil {
			log.Printf("Ошибка при пакетном обновлении DNS-запросов: %v", err)
			tx.Rollback()
			return
		}
	}

	// Фиксируем транзакцию
	if err := tx.Commit(); err != nil {
		log.Printf("Ошибка при коммите транзакции: %v", err)
		tx.Rollback()
		return
	}

	// Обновляем позицию в файле
	pos, err := file.Seek(0, 1)
	if err != nil {
		log.Printf("Ошибка получения позиции файла: %v", err)
		return
	}
	*offset = pos
}

// checkExpiredSubscriptions проверяет истекшие подписки и обновляет статус
func checkExpiredSubscriptions(memDB *sql.DB) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	rows, err := memDB.Query("SELECT email, sub_end, uuid, enabled, renew FROM clients_stats WHERE sub_end")
	if err != nil {
		log.Println("Ошибка при получении данных из БД:", err)
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

	now := time.Now()
	for rows.Next() {
		var s subscription
		err := rows.Scan(&s.Email, &s.SubEnd, &s.UUID, &s.Enabled, &s.Renew)
		if err != nil {
			log.Println("Ошибка сканирования строки:", err)
			continue
		}
		subscriptions = append(subscriptions, s)
	}

	if err = rows.Err(); err != nil {
		log.Println("Ошибка при обработке строк:", err)
		return
	}

	for _, s := range subscriptions {
		if s.SubEnd != "" {
			subEnd, err := time.Parse("2006-01-02-15", s.SubEnd)
			if err != nil {
				log.Printf("Ошибка парсинга даты для %s: %v", s.Email, err)
				continue
			}

			if subEnd.Before(now) {
				notifiedMutex.Lock()
				if !notifiedUsers[s.Email] {
					log.Printf("❌ Подписка истекла для %s (%s)", s.Email, s.SubEnd)
					notifiedUsers[s.Email] = true
				}
				notifiedMutex.Unlock()

				if s.Renew >= 1 {
					offset := fmt.Sprintf("%d", s.Renew)
					err = adjustDateOffset(memDB, s.Email, offset, now)
					if err != nil {
						log.Printf("Ошибка продления подписки для %s: %v", s.Email, err)
						continue
					}
					log.Printf("✅ Автопродление подписки пользователя %s на %d", s.Email, s.Renew)

					notifiedMutex.Lock()
					notifiedUsers[s.Email] = false // Сбрасываем уведомление при продлении
					notifiedMutex.Unlock()

					// Включаем пользователя, если он был отключен
					if s.Enabled == "false" {
						err = updateLuaUuid(s.UUID, true)
						if err != nil {
							log.Printf("Ошибка при включении пользователя %s: %v", s.Email, err)
							continue
						}
						updateEnabledInDB(memDB, s.UUID, "true")
						log.Printf("Пользователь %s включен", s.Email)
					}
				} else if s.Enabled == "true" {
					err = updateLuaUuid(s.UUID, false)
					if err != nil {
						log.Printf("Ошибка при отключении пользователя %s: %v", s.Email, err)
					} else {
						log.Printf("Пользователь %s отключен", s.Email)
					}
					updateEnabledInDB(memDB, s.UUID, "false")
				}
			} else {
				if s.Enabled == "false" {
					err = updateLuaUuid(s.UUID, true)
					if err != nil {
						log.Printf("Ошибка при включении пользователя %s: %v", s.Email, err)
						continue
					}
					updateEnabledInDB(memDB, s.UUID, "true")
					log.Printf("✅ Возобновление подписки, пользователь %s включен (%s)", s.Email, s.SubEnd)
				}
			}
		}
	}
}

// User представляет структуру пользователя с email и enabled
type User struct {
	Email   string `json:"email"`
	Enabled string `json:"enabled"`
	Sub_end string `json:"sub_end"`
	Lim_ip  string `json:"lim_ip"`
	Renew   int    `json:"renew"`
}

// usersHandler возвращает список пользователей в формате JSON
func usersHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Неверный метод. Используйте GET", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		// Запрос с двумя столбцами: email и enabled
		rows, err := memDB.Query("SELECT email, enabled, sub_end, renew, lim_ip FROM clients_stats")
		if err != nil {
			log.Printf("Ошибка выполнения SQL-запроса: %v", err)
			http.Error(w, "Ошибка выполнения запроса", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.Email, &user.Enabled, &user.Sub_end, &user.Renew, &user.Lim_ip); err != nil {
				log.Printf("Ошибка чтения результата: %v", err)
				http.Error(w, "Ошибка обработки данных", http.StatusInternalServerError)
				return
			}
			users = append(users, user)
		}

		// Проверка ошибок после итерации по строкам
		if err := rows.Err(); err != nil {
			log.Printf("Ошибка в результате запроса: %v", err)
			http.Error(w, "Ошибка обработки данных", http.StatusInternalServerError)
			return
		}

		// Отправляем список пользователей в формате JSON
		if err := json.NewEncoder(w).Encode(users); err != nil {
			log.Printf("Ошибка кодирования JSON: %v", err)
			http.Error(w, "Ошибка формирования ответа", http.StatusInternalServerError)
			return
		}
	}
}

// statsHandler возвращает статистику сервера и клиентов
func statsHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Устанавливаем заголовок ответа
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		// Проверяем, что используется метод GET
		if r.Method != http.MethodGet {
			http.Error(w, "Неверный метод. Используйте GET", http.StatusMethodNotAllowed)
			return
		}

		// Проверяем, что база данных инициализирована
		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		// Статистика сервера
		stats := " 🌐 Статистика сервера:\n============================\n"
		stats += fmt.Sprintf("%-10s %-10s %-10s %-10s %-10s\n", "Source", "Sess Up", "Sess Down", "Upload", "Download")
		stats += "-----------------------------------------------------\n"

		// Запрос статистики сервера
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
			log.Printf("Ошибка выполнения SQL-запроса: %v", err)
			http.Error(w, "Ошибка выполнения запроса", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Обрабатываем строки статистики сервера
		for rows.Next() {
			var source, sessUp, sessDown, upload, download string
			if err := rows.Scan(&source, &sessUp, &sessDown, &upload, &download); err != nil {
				log.Printf("Ошибка чтения результата: %v", err)
				http.Error(w, "Ошибка обработки данных", http.StatusInternalServerError)
				return
			}
			stats += fmt.Sprintf("%-10s %-10s %-10s %-10s %-10s\n", source, sessUp, sessDown, upload, download)
		}

		// Статистика клиентов
		stats += "\n 📊 Статистика клиентов:\n============================\n"
		// Добавляем заголовок для столбца Renew после Sub_end
		stats += fmt.Sprintf("%-12s %-9s %-8s %-14s %-8s %-10s %-10s %-10s %-10s %-6s %s\n",
			"Email", "Status", "Enabled", "Sub_end", "Renew", "Sess Up", "Sess Down", "Uplink", "Downlink", "LimIP", "IP")
		stats += "---------------------------------------------------------------------------------------------------------------------------\n"

		// Запрос статистики клиентов с добавлением столбца renew
		rows, err = memDB.Query(`
            SELECT email AS "Email",
                status AS "Status",
                enabled AS "Enabled",
                sub_end AS "Sub end",
                renew AS "Renew",
                ips AS "Ips",
                lim_ip AS "Lim_ip",
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
                END AS "Downlink"
            FROM clients_stats;
        `)
		if err != nil {
			log.Printf("Ошибка выполнения SQL-запроса: %v", err)
			http.Error(w, "Ошибка выполнения запроса", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Обрабатываем строки статистики клиентов
		for rows.Next() {
			var email, status, enabled, sub_end, sessUp, sessDown, uplink, downlink, ipLimit, ips string
			var renew int // Переменная для столбца renew (тип INTEGER)
			if err := rows.Scan(&email, &status, &enabled, &sub_end, &renew, &ips, &ipLimit, &sessUp, &sessDown, &uplink, &downlink); err != nil {
				log.Printf("Ошибка чтения результата: %v", err)
				http.Error(w, "Ошибка обработки данных", http.StatusInternalServerError)
				return
			}

			// Формируем строку клиента с добавлением значения renew
			stats += fmt.Sprintf("%-12s %-9s %-8s %-14s %-8d %-10s %-10s %-10s %-10s %-6s %s\n",
				email, status, enabled, sub_end, renew, sessUp, sessDown, uplink, downlink, ipLimit, ips)
		}

		// Отправляем статистику клиенту
		fmt.Fprintln(w, stats)
	}
}

// dnsStatsHandler возвращает статистику DNS-запросов
func dnsStatsHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if r.Method != http.MethodGet {
			http.Error(w, "Неверный метод. Используйте GET", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
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

		stats := " 📊 Статистика dns запросов:\n============================\n"
		stats += fmt.Sprintf("%-12s %-6s %-s\n", "Email", "Count", "Domain")
		stats += "-------------------------------------------------------------\n"
		rows, err := memDB.Query(`
			SELECT email AS "Email", count AS "Count", domain AS "Domain"
			FROM dns_stats
			WHERE email = ?
			ORDER BY count DESC
			LIMIT ?`, email, count)
		if err != nil {
			log.Printf("Ошибка выполнения SQL-запроса: %v", err)
			http.Error(w, "Ошибка выполнения запроса", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var email, domain string
			var count int
			if err := rows.Scan(&email, &count, &domain); err != nil {
				log.Printf("Ошибка чтения результата: %v", err)
				http.Error(w, "Ошибка обработки данных", http.StatusInternalServerError)
				return
			}
			stats += fmt.Sprintf("%-12s %-6d %-s\n", email, count, domain)
		}

		fmt.Fprintln(w, stats)
	}
}

// updateIPLimitHandler обновляет лимит IP для пользователя
func updateIPLimitHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		// Проверяем, что метод запроса - PATCH
		if r.Method != http.MethodPatch {
			http.Error(w, "Неверный метод. Используйте PATCH", http.StatusMethodNotAllowed)
			return
		}

		// Проверка инициализации базы данных
		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		// Читаем параметры из формы (POST или PATCH тело запроса)
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Ошибка парсинга формы", http.StatusBadRequest)
			return
		}

		// Извлекаем параметры
		username := r.FormValue("username")
		ipLimit := r.FormValue("lim_ip")

		// Проверяем, что параметры не пустые
		if username == "" || ipLimit == "" {
			http.Error(w, "Неверные параметры. Используйте username и lim_ip", http.StatusBadRequest)
			return
		}

		// Проверяем, что lim_ip - это число в пределах от 1 до 100
		ipLimitInt, err := strconv.Atoi(ipLimit)
		if err != nil {
			http.Error(w, "lim_ip должен быть числом", http.StatusBadRequest)
			return
		}

		if ipLimitInt < 1 || ipLimitInt > 100 {
			http.Error(w, "lim_ip должен быть в пределах от 1 до 100", http.StatusBadRequest)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		// Выполняем обновление в базе данных
		query := "UPDATE clients_stats SET lim_ip = ? WHERE email = ?"
		result, err := memDB.Exec(query, ipLimit, username)
		if err != nil {
			http.Error(w, "Ошибка обновления lim_ip", http.StatusInternalServerError)
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			http.Error(w, fmt.Sprintf("Пользователь '%s' не найден", username), http.StatusNotFound)
			return
		}

		// Ответ о успешном обновлении
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "lim_ip для '%s' обновлен до '%s'\n", username, ipLimit)
	}
}

// deleteDNSStatsHandler удаляет статистику DNS
func deleteDNSStatsHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Неверный метод. Используйте POST", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		_, err := memDB.Exec("DELETE FROM dns_stats")
		if err != nil {
			http.Error(w, "Не удалось удалить записи из dns_stats", http.StatusInternalServerError)
			return
		}

		log.Printf("Received request to delete dns_stats from %s", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		fmt.Println(w, "dns_stats deleted successfully")
	}
}

// parseAndAdjustDate парсит смещение даты и корректирует её
func parseAndAdjustDate(offset string, baseDate time.Time) (time.Time, error) {
	matches := dateOffsetRegex.FindStringSubmatch(offset)
	if matches == nil {
		return time.Time{}, fmt.Errorf("неверный формат: %s", offset)
	}

	sign := matches[1] // + или -
	daysStr := matches[2]
	hoursStr := matches[3]

	// Конвертируем в числа
	days, _ := strconv.Atoi(daysStr)
	hours := 0
	if hoursStr != "" {
		hours, _ = strconv.Atoi(hoursStr)
	}

	// Определяем направление (прибавлять или убавлять)
	if sign == "-" {
		days = -days
		hours = -hours
	}

	// Корректируем дату
	newDate := baseDate.AddDate(0, 0, days).Add(time.Duration(hours) * time.Hour)
	return newDate, nil
}

// adjustDateOffset корректирует дату окончания подписки для пользователя
func adjustDateOffset(memDB *sql.DB, email, offset string, baseDate time.Time) error {
	offset = strings.TrimSpace(offset)

	if offset == "0" {
		_, err := memDB.Exec("UPDATE clients_stats SET sub_end = '' WHERE email = ?", email)
		if err != nil {
			return fmt.Errorf("ошибка обновления БД: %v", err)
		}
		log.Printf("Для email %s установлено безлимитное ограничение по времени", email)
		return nil
	}

	newDate, err := parseAndAdjustDate(offset, baseDate)
	if err != nil {
		return fmt.Errorf("неверный формат offset: %v", err)
	}

	_, err = memDB.Exec("UPDATE clients_stats SET sub_end = ? WHERE email = ?", newDate.Format("2006-01-02-15"), email)
	if err != nil {
		return fmt.Errorf("ошибка обновления БД: %v", err)
	}

	log.Printf("Дата подписки для %s обновлена: %s -> %s (offset: %s)", email, baseDate.Format("2006-01-02-15"), newDate.Format("2006-01-02-15"), offset)
	return nil
}

// adjustDateOffsetHandler корректирует дату окончания подписки
func adjustDateOffsetHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "Неверный метод. Используйте PATCH", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Ошибка парсинга данных", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		offset := r.FormValue("offset")

		if email == "" || offset == "" {
			http.Error(w, "email и offset обязательны", http.StatusBadRequest)
			return
		}

		dbMutex.Lock()
		defer dbMutex.Unlock()

		baseDate := time.Now().UTC()

		var subEndStr string
		err := memDB.QueryRow("SELECT sub_end FROM clients_stats WHERE email = ?", email).Scan(&subEndStr)
		if err != nil && err != sql.ErrNoRows {
			http.Error(w, "Ошибка запросы к БД", http.StatusInternalServerError)
			return
		}

		if subEndStr != "" {
			baseDate, err = time.Parse("2006-01-02-15", subEndStr)
			if err != nil {
				http.Error(w, "Ошибка парсинга sub_end", http.StatusInternalServerError)
				return
			}
		}

		err = adjustDateOffset(memDB, email, offset, baseDate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		checkExpiredSubscriptions(memDB)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Дата подписки для %s обновлена с offset %s\n", email, offset)
	}
}

// updateLuaUuid обновляет статус UUID в файле Lua
func updateLuaUuid(uuid string, enabled bool) error {
	data, err := os.ReadFile(config.LUAFilePath)
	if err != nil {
		log.Printf("Ошибка чтения файла Lua %s: %v", config.LUAFilePath, err)
		return err
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
		return fmt.Errorf("ошибка записи в файл Lua: %v", err)
	}

	err = exec.Command("systemctl", "reload", "haproxy").Run()
	if err != nil {
		log.Printf("Ошибка перезагрузки Haproxy (reload): %v", err)

		err = exec.Command("systemctl", "restart", "haproxy").Run()
		if err != nil {
			return fmt.Errorf("ошибка перезапуска HAProxy (restart): %v", err)
		}
		log.Printf("Haproxy успешно перезапущен (restart) после неудачного reload")
	} else {
		log.Printf("Haproxy успешно перезагружен (reload)")
	}

	return nil
}

// setEnabledHandler устанавливает статус enabled для пользователя
func setEnabledHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "Неверный метод. Используйте PATCH", http.StatusMethodNotAllowed)
			return
		}

		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Ошибка парсинга данных", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		enabledStr := r.FormValue("enabled")

		if email == "" {
			http.Error(w, "email обязателен", http.StatusBadRequest)
			return
		}

		// Устанавливаем значение enabled: по умолчанию true, если параметр не передан
		var enabled bool
		if enabledStr == "" {
			enabled = true
			enabledStr = "true"
		} else {
			var err error
			enabled, err = strconv.ParseBool(enabledStr)
			if err != nil {
				http.Error(w, "enabled должно быть true или false", http.StatusBadRequest)
				return
			}
		}

		// Извлекаем uuid из базы данных по email
		var uuid string
		var err error
		err = memDB.QueryRow("SELECT uuid FROM clients_stats WHERE email = ?", email).Scan(&uuid)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Пользователь с таким email не найден", http.StatusNotFound)
				return
			}
			log.Printf("Ошибка запроса к БД: %v", err)
			http.Error(w, "Ошибка сервера при запросе к БД", http.StatusInternalServerError)
			return
		}

		luaMutex.Lock()
		defer luaMutex.Unlock()

		err = updateLuaUuid(uuid, enabled)
		if err != nil {
			log.Printf("Ошибка обновления Lua-файла %v", err)
			http.Error(w, "Ошибка обновления файла авторизация", http.StatusInternalServerError)
			return
		}

		// Обновляем значение enabled в memDB сразу
		updateEnabledInDB(memDB, uuid, enabledStr)

		log.Printf("Для email %s (uuid %s) установлено значение = %t", email, uuid, enabled)
		w.WriteHeader(http.StatusOK)
	}
}

// updateRenewHandler обновляет поле renew для пользователя через HTTP-запрос
func updateRenewHandler(memDB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, что используется метод PATCH
		if r.Method != http.MethodPatch {
			http.Error(w, "Неверный метод. Используйте PATCH", http.StatusMethodNotAllowed)
			return
		}

		// Проверяем, что база данных инициализирована
		if memDB == nil {
			http.Error(w, "База данных не инициализирована", http.StatusInternalServerError)
			return
		}

		// Разбираем параметры из формы
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Ошибка парсинга данных", http.StatusBadRequest)
			return
		}

		// Извлекаем значения параметров email и renew
		email := r.FormValue("email")
		renewStr := r.FormValue("renew")

		// Проверяем, что email передан (обязательный параметр)
		if email == "" {
			http.Error(w, "email обязателен", http.StatusBadRequest)
		}

		// Обрабатываем параметр renew (необязательный, по умолчанию 0)
		var renew int
		if renewStr == "" {
			renew = 0
		} else {
			var err error
			renew, err = strconv.Atoi(renewStr)
			if err != nil {
				http.Error(w, "renew должно быть целым числом", http.StatusBadRequest)
				return
			}
			if renew < 0 {
				http.Error(w, "renew не может быть отрицательным", http.StatusBadRequest)
				return
			}
		}

		// Блокируем доступ к базе данных для безопасного обновления
		dbMutex.Lock()
		defer dbMutex.Unlock()

		// Выполняем SQL-запрос для обновления столбца renew в таблице clients_stats
		result, err := memDB.Exec("UPDATE clients_stats SET renew = ? WHERE email = ?", renew, email)
		if err != nil {
			log.Printf("Ошибка обновления renew для %s: %v", email, err)
			http.Error(w, "Ошибка обновления базы данных", http.StatusInternalServerError)
			return
		}

		// Проверяем, сколько строк было обновлено
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("Ошибка получения RowsAffected: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		// Если ни одна строка не обновлена, значит пользователь не найден
		if rowsAffected == 0 {
			http.Error(w, fmt.Sprintf("Пользователь '%s' не найден", email), http.StatusNotFound)
			return
		}

		// Логируем успешное обновление и отправляем ответ клиенту
		log.Printf("Для пользователя %s установлено автопродление = %d", email, renew)
		w.WriteHeader(http.StatusOK)
	}
}

// startAPIServer запускает HTTP-сервер с graceful shutdown
func startAPIServer(ctx context.Context, memDB *sql.DB, wg *sync.WaitGroup) {
	server := &http.Server{
		Addr:    "127.0.0.1:" + config.Port,
		Handler: nil, // Используем стандартный маршрутизатор
	}

	// Регистрируем маршруты
	http.HandleFunc("/users", usersHandler(memDB))
	http.HandleFunc("/stats", statsHandler(memDB))
	http.HandleFunc("/dns_stats", dnsStatsHandler(memDB))
	http.HandleFunc("/update_lim_ip", updateIPLimitHandler(memDB))
	http.HandleFunc("/delete_dns_stats", deleteDNSStatsHandler(memDB))
	http.HandleFunc("/adjust-date", adjustDateOffsetHandler(memDB))
	http.HandleFunc("/set-enabled", setEnabledHandler(memDB))
	http.HandleFunc("/update_renew", updateRenewHandler(memDB))

	// Запускаем сервер в отдельной горутине
	go func() {
		log.Printf("API server starting on 127.0.0.1:%s...", config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Ошибка запуска сервера: %v", err)
		}
	}()

	// Ожидаем сигнала завершения
	<-ctx.Done()
	log.Println("Остановка API-сервера...")

	// Создаем контекст с таймаутом для graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Останавливаем сервер
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Ошибка при остановке сервера: %v", err)
	}
	log.Println("API-сервер успешно остановлен")

	// Уменьшаем счетчик WaitGroup только после полной остановки
	wg.Done()
}

// syncToFileDB синхронизирует данные из памяти в файл базы данных
func syncToFileDB(memDB *sql.DB) error {
	// Проверяем существует ли файл
	_, err := os.Stat(config.DatabasePath)
	fileExists := !os.IsNotExist(err)

	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Открываем или создаем fileDB
	fileDB, err := sql.Open("sqlite3", config.DatabasePath)
	if err != nil {
		return fmt.Errorf("ошибка открытия fileDB: %v", err)
	}
	defer fileDB.Close()

	if !fileExists {
		// Файл не суещствует, инициализируем его
		err = initDB(fileDB)
		if err != nil {
			return fmt.Errorf("ошибка инициализации fileDB: %v", err)
		}
	}

	// Список таблиц для синхронизации
	tables := []string{"clients_stats", "traffic_stats", "dns_stats"}

	// Начинаем транзакцию в fileDB
	tx, err := fileDB.Begin()
	if err != nil {
		return fmt.Errorf("ошибка начала транзакции в fileDB: %v", err)
	}

	// Проходим по каждой таблице
	for _, table := range tables {
		// Очищаем таблицу в fileDB
		_, err = tx.Exec(fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка очистки таблицы %s в fileDB: %v", table, err)
		}

		// Получаем данные из memDB
		rows, err := memDB.Query(fmt.Sprintf("SELECT * FROM %s", table))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка получения данных из memDB для таблицы %v: %v", table, err)
		}
		defer rows.Close()

		// Получаем информацию о столбцах
		columns, err := rows.Columns()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка получения столбцов: %v", err)
		}

		// Подготовка запроса для вставки
		placeholders := strings.Repeat("?,", len(columns)-1) + "?"
		insertQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ","), placeholders)
		stmt, err := tx.Prepare(insertQuery)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка подготовки запроса: %v", err)
		}
		defer stmt.Close()

		// Копируем строки
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		for rows.Next() {
			if err := rows.Scan(valuePtrs...); err != nil {
				tx.Rollback()
				return fmt.Errorf("ошибка сканирования строки: %v", err)
			}
			_, err = stmt.Exec(values...)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("ошибка вставки строки: %v", err)
			}
		}
	}

	// Завершаем транзакцию
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ошибка коммита транзакции: %v", err)
	}

	return nil
}

// main - основная функция программы
func main() {
	// Проверка лицензии
	license.VerifyLicense()

	fmt.Println("Starting xCore application...")
	// Загружаем конфигурацию
	if err := loadConfig(".env"); err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}
	flag.Parse()

	// Проверяем, существует ли файл базы данных
	_, err := os.Stat(config.DatabasePath)
	fileExists := !os.IsNotExist(err)

	// Создаём memDB
	memDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal("Ошибка создания in-memory базы:", err)
	}
	defer memDB.Close()

	if fileExists {
		// Файл существует, открываем fileDB
		fileDB, err := sql.Open("sqlite3", config.DatabasePath)
		if err != nil {
			log.Fatal("Ошибка открытия базы данных:", err)
		}
		defer fileDB.Close()

		// Инициализируем fileDB (если нужно)
		err = initDB(fileDB)
		if err != nil {
			log.Fatal("Ошибка инициализации базы данных:", err)
		}

		// Копируем данные из fileDB в memDB
		err = backupDB(fileDB, memDB)
		if err != nil {
			log.Fatal("Ошибка копирования данных в память:", err)
		}
	} else {
		// Файл не существует, инициализируем memDB
		err = initDB(memDB)
		if err != nil {
			log.Fatal("Ошибка инициализации in-memory базы:", err)
		}
	}

	// Очищаем содержимое файла перед чтением
	err = os.Truncate(config.DirXray+"access.log", 0)
	if err != nil {
		fmt.Println("Ошибка очистки файла:", err)
		return
	}

	// Открываем файл access.log
	accessLog, err := os.Open(config.DirXray + "access.log")
	if err != nil {
		log.Fatalf("Ошибка при открытии access.log: %v", err)
	}
	defer accessLog.Close()

	// Создаём контекст для graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Канал для получения сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Запуск API-сервера
	wg.Add(1)
	go startAPIServer(ctx, memDB, &wg)

	// Логирование лишних IP каждую 1 минуту
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
					log.Printf("Ошибка логирования IP: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Синхронизация данных каждые 5 минут
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Проверка подписки
				checkExpiredSubscriptions(memDB)

				// Обработка файла Lua
				luaConf, err := os.Open(config.LUAFilePath)
				if err != nil {
					fmt.Println("Ошибка открытия файла:", err)
				} else {
					parseAndUpdate(memDB, luaConf)
					luaConf.Close()
				}

				// Синхронизация данных
				if err := syncToFileDB(memDB); err != nil {
					log.Printf("Ошибка синхронизации: %v", err)
				} else {
					log.Println("База данных успешно синхронизирована.")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Основной цикл обновления данных
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		var offset int64 = 0
		for {
			select {
			case <-ticker.C:
				// starttime := time.Now()

				clients := extractUsersXrayServer()
				if err := addUserToDB(memDB, clients); err != nil {
					log.Printf("Ошибка при добавлении пользователя: %v", err)
				}
				if err := delUserFromDB(memDB, clients); err != nil {
					log.Printf("Ошибка при удалении пользователей: %v", err)
				}

				apiData, err := getApiResponse()
				if err != nil {
					log.Printf("Ошибка получения данных из API: %v", err)
				} else {
					updateProxyStats(memDB, apiData)
					updateClientStats(memDB, apiData)
				}
				readNewLines(memDB, accessLog, &offset)

				// elapsed := time.Since(starttime)
				// fmt.Printf("Время выполнения программы: %s\n", elapsed)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Ожидание сигнала завершения
	<-sigChan
	log.Println("Получен сигнал завершения, сохраняем данные...")
	cancel() // Останавливаем все горутины

	// Синхронизация данных перед завершением
	if err := syncToFileDB(memDB); err != nil {
		log.Printf("Ошибка синхронизации данных в fileDB: %v", err)
	} else {
		log.Println("Данные успешно сохранены в файл базы данных")
	}

	wg.Wait()
	log.Println("Программа завершена")
}

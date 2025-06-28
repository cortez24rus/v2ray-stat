package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"v2ray-stat/config"
	"v2ray-stat/db" // Импорт пакета db для проверки таблиц
)

var (
	dbMutex sync.Mutex
)

// logExcessIPs логирует избыточные IP-адреса в файл
func logExcessIPs(memDB *sql.DB, logFile *os.File, cfg *config.Config) error {
	startTime := time.Now()
	log.Printf("[%s] Начало выполнения logExcessIPs", startTime.Format("2006/01/02 15:04:05"))

	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Проверка существования таблицы clients_stats
	log.Printf("[%s] Проверка существования таблицы clients_stats", time.Now().Format("2006/01/02 15:04:05"))
	if !db.CheckTableExists(memDB, "clients_stats") {
		log.Printf("[%s] Таблица clients_stats отсутствует, попытка переинициализации", time.Now().Format("2006/01/02 15:04:05"))
		if err := db.InitDB(memDB); err != nil {
			log.Printf("[%s] Ошибка переинициализации базы данных: %v", time.Now().Format("2006/01/02 15:04:05"), err)
			return fmt.Errorf("не удалось переинициализировать базу данных: %v", err)
		}
		log.Printf("[%s] База данных успешно переинициализирована", time.Now().Format("2006/01/02 15:04:05"))
	}

	currentTime := time.Now().Format("2006/01/02 15:04:05")
	log.Printf("[%s] Выполнение запроса к таблице clients_stats", currentTime)

	rows, err := memDB.Query("SELECT email, lim_ip, ips FROM clients_stats")
	if err != nil {
		log.Printf("[%s] Ошибка при запросе к таблице clients_stats: %v", time.Now().Format("2006/01/02 15:04:05"), err)
		return fmt.Errorf("ошибка при запросе к базе данных: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("[%s] Ошибка при закрытии результата запроса: %v", time.Now().Format("2006/01/02 15:04:05"), err)
		}
	}()

	log.Printf("[%s] Начало обработки строк результата", time.Now().Format("2006/01/02 15:04:05"))
	for rows.Next() {
		var email, ipAddresses string
		var ipLimit int

		err := rows.Scan(&email, &ipLimit, &ipAddresses)
		if err != nil {
			log.Printf("[%s] Ошибка при чтении строки для email %s: %v", time.Now().Format("2006/01/02 15:04:05"), email, err)
			return fmt.Errorf("ошибка при чтении строки: %v", err)
		}
		log.Printf("[%s] Обработка email: %s, lim_ip: %d, IPs: %s", time.Now().Format("2006/01/02 15:04:05"), email, ipLimit, ipAddresses)

		if ipLimit == 0 {
			continue
		}

		// Обработка списка IP-адресов
		ipAddresses = strings.Trim(ipAddresses, "[]")
		ipList := strings.Split(ipAddresses, ",")

		filteredIPList := make([]string, 0, len(ipList))
		for _, ips := range ipList {
			ips = strings.TrimSpace(ips)
			if ips != "" {
				filteredIPList = append(filteredIPList, ips)
			}
		}
		log.Printf("[%s] Отфильтрованный список IP для email %s: %v", time.Now().Format("2006/01/02 15:04:05"), email, filteredIPList)

		// Проверка превышения лимита IP и запись в лог
		if len(filteredIPList) > ipLimit {
			excessIPs := filteredIPList[ipLimit:]
			log.Printf("[%s] Обнаружено %d избыточных IP для email %s: %v", time.Now().Format("2006/01/02 15:04:05"), len(excessIPs), email, excessIPs)
			for _, ips := range excessIPs {
				logData := fmt.Sprintf("%s [LIMIT_IP] Email = %s || SRC = %s\n", currentTime, email, ips)
				_, err := logFile.WriteString(logData)
				if err != nil {
					log.Printf("[%s] Ошибка записи в лог для email %s, IP %s: %v", time.Now().Format("2006/01/02 15:04:05"), email, ips, err)
					return fmt.Errorf("ошибка записи в файл логов: %v", err)
				}
				log.Printf("[%s] Успешно записан избыточный IP %s для email %s", time.Now().Format("2006/01/02 15:04:05"), ips, email)
			}
		}
	}

	// Проверка ошибок при итерации строк
	if err := rows.Err(); err != nil {
		log.Printf("[%s] Ошибка при обработке строк результата: %v", time.Now().Format("2006/01/02 15:04:05"), err)
		return fmt.Errorf("ошибка при обработке строк: %v", err)
	}

	log.Printf("[%s] Завершение logExcessIPs, время выполнения: %v", time.Now().Format("2006/01/02 15:04:05"), time.Since(startTime))
	return nil
}

// MonitorExcessIPs запускает задачу мониторинга избыточных IP
func MonitorExcessIPs(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		startTime := time.Now()
		log.Printf("[%s] Запуск MonitorExcessIPs", startTime.Format("2006/01/02 15:04:05"))

		// Открытие файла логов один раз в начале рутины
		logFile, err := os.OpenFile(cfg.XipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("[%s] Ошибка открытия файла логов %s: %v", time.Now().Format("2006/01/02 15:04:05"), cfg.XipLogFile, err)
			return
		}
		defer func() {
			log.Printf("[%s] Закрытие файла логов %s", time.Now().Format("2006/01/02 15:04:05"), cfg.XipLogFile)
			if err := logFile.Close(); err != nil {
				log.Printf("[%s] Ошибка при закрытии файла логов: %v", time.Now().Format("2006/01/02 15:04:05"), err)
			}
		}()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				log.Printf("[%s] Запуск цикла логирования избыточных IP", time.Now().Format("2006/01/02 15:04:05"))
				if err := logExcessIPs(memDB, logFile, cfg); err != nil {
					log.Printf("[%s] Ошибка при логировании IP: %v", time.Now().Format("2006/01/02 15:04:05"), err)
				} else {
					log.Printf("[%s] Логирование IP выполнено успешно", time.Now().Format("2006/01/02 15:04:05"))
				}
			case <-ctx.Done():
				log.Printf("[%s] Мониторинг избыточных IP завершен", time.Now().Format("2006/01/02 15:04:05"))
				return
			}
		}
	}()
}

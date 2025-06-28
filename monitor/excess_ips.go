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
	"v2ray-stat/db"
)

var (
	dbMutex sync.Mutex
)

// logExcessIPs логирует избыточные IP-адреса в файл
func logExcessIPs(memDB *sql.DB, logFile *os.File) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Проверка существования таблицы clients_stats
	if !db.CheckTableExists(memDB, "clients_stats") {
		log.Printf("Таблица clients_stats отсутствует, попытка переинициализации")
		if err := db.InitDB(memDB); err != nil {
			log.Printf("Ошибка переинициализации базы данных: %v", err)
			return fmt.Errorf("не удалось переинициализировать базу данных: %v", err)
		}
	}

	currentTime := time.Now().Format("2006/01/02 15:04:05")
	rows, err := memDB.Query("SELECT email, lim_ip, ips FROM clients_stats")
	if err != nil {
		log.Printf("Ошибка при запросе к таблице clients_stats: %v", err)
		return fmt.Errorf("ошибка при запросе к базе данных: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var email, ipAddresses string
		var ipLimit int

		if err := rows.Scan(&email, &ipLimit, &ipAddresses); err != nil {
			log.Printf("Ошибка при чтении строки для email %s: %v", email, err)
			return fmt.Errorf("ошибка при чтении строки: %v", err)
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
				if _, err := logFile.WriteString(logData); err != nil {
					log.Printf("Ошибка записи в лог для email %s, IP %s: %v", email, ips, err)
					return fmt.Errorf("ошибка записи в файл логов: %v", err)
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Ошибка при обработке строк результата: %v", err)
		return fmt.Errorf("ошибка при обработке строк: %v", err)
	}

	return nil
}

// MonitorExcessIPs запускает задачу мониторинга избыточных IP
func MonitorExcessIPs(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		logFile, err := os.OpenFile(cfg.XipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Ошибка открытия файла логов %s: %v", cfg.XipLogFile, err)
			return
		}
		defer logFile.Close()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := logExcessIPs(memDB, logFile); err != nil {
					log.Printf("Ошибка при логировании IP: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

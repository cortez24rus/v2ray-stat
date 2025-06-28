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
)

var (
	dbMutex sync.Mutex
)

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

// Запуск задачи логирования избыточных IP
func MonitorExcessIPs(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(15 * time.Minute)
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

package stats

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/constant"
	"v2ray-stat/manager"
	"v2ray-stat/telegram"
	"v2ray-stat/util"
)

// SendDailyReport sends a daily Telegram notification with system and network stats.
func SendDailyReport(manager *manager.DatabaseManager, cfg *config.Config) {
	if cfg.Telegram.BotToken == "" || cfg.Telegram.ChatID == "" {
		log.Println("Error: cannot send daily report: TelegramBotToken or TelegramChatID is missing")
		return
	}

	coreVersion := getCoreVersion(cfg)
	ipv4, ipv6 := getIPAddresses()
	uptime := GetUptime()
	loadAverage := GetLoadAverage()
	memoryUsage := GetMemoryUsage()
	tcpCount, udpCount := getConnectionCounts()

	var uplink, downlink uint64
	err := manager.Execute(func(db *sql.DB) error {
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Ошибка при старте транзакции: %v", err)
			return fmt.Errorf("ошибка при старте транзакции: %v", err)
		}
		defer tx.Rollback()

		err = tx.QueryRow("SELECT uplink, downlink FROM traffic_stats WHERE source = 'direct'").Scan(&uplink, &downlink)
		if err != nil {
			if err == sql.ErrNoRows {
				uplink, downlink = 0, 0
				return nil
			}
			log.Printf("Ошибка при запросе к таблице traffic_stats: %v", err)
			return fmt.Errorf("ошибка при запросе к базе данных: %v", err)
		}

		if err := tx.Commit(); err != nil {
			log.Printf("Ошибка при фиксации транзакции: %v", err)
			return fmt.Errorf("ошибка при фиксации транзакции: %v", err)
		}
		return nil
	})
	if err != nil {
		log.Printf("Error querying traffic stats: %v", err)
		uplink, downlink = 0, 0
	}

	totalTraffic := util.FormatData(float64(uplink+downlink), "byte")
	uplinkTraffic := util.FormatData(float64(uplink), "byte")
	downlinkTraffic := util.FormatData(float64(downlink), "byte")

	serviceStatus := GetStatus(cfg.Services)
	if serviceStatus == "" {
		serviceStatus = "no services configured"
	}

	message := fmt.Sprintf(
		"⚙️ v2ray-stat version: %s\n"+
			"🚀 %s version: %s\n"+
			"🌐 IPv4: %s\n"+
			"🌐 IPv6: %s\n"+
			"⏳ Uptime: %s\n"+
			"📈 System Load: %s\n"+
			"📋 RAM: %s\n"+
			"🔹 TCP: %d\n"+
			"🔸 UDP: %d\n"+
			"🚦 Traffic: %s (↑%s,↓%s)\n"+
			"ℹ️ Status: %s",
		constant.Version, cfg.V2rayStat.Type, coreVersion, ipv4, ipv6, uptime, loadAverage, memoryUsage, tcpCount, udpCount, totalTraffic, uplinkTraffic, downlinkTraffic, serviceStatus,
	)

	if err := telegram.SendNotification(cfg.Telegram.BotToken, cfg.Telegram.ChatID, message); err != nil {
		log.Printf("Error sending daily report to Telegram: %v", err)
	} else {
		log.Println("Daily report sent successfully to Telegram")
	}
}

// MonitorDailyReport schedules the daily report to run every 24 hours.
func MonitorDailyReport(ctx context.Context, manager *manager.DatabaseManager, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		SendDailyReport(manager, cfg)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				SendDailyReport(manager, cfg)
			case <-ctx.Done():
				return
			}
		}
	}()
}

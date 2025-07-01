package stats

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/constant"
	"v2ray-stat/telegram"
)

// SendDailyReport sends a daily Telegram notification with system and network stats.
func SendDailyReport(memDB *sql.DB, cfg *config.Config) {
	if cfg.TelegramBotToken == "" || cfg.TelegramChatID == "" {
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
	err := memDB.QueryRow("SELECT uplink, downlink FROM traffic_stats WHERE source = 'direct'").Scan(&uplink, &downlink)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Error querying traffic stats: %v", err)
		}
		uplink, downlink = 0, 0
	}

	totalTraffic := formatBytes(uplink + downlink)
	uploadTraffic := formatBytes(uplink)
	downloadTraffic := formatBytes(downlink)

	serviceStatus := GetStatus(cfg.Services)
	if serviceStatus == "" {
		serviceStatus = "no services configured"
	}

	message := fmt.Sprintf(
		"⚙️ v2ray-stat version: %s\n"+
			"📡 %s version: %s\n"+
			"🌐 IPv4: %s\n"+
			"🌐 IPv6: %s\n"+
			"⏳ Uptime: %s\n"+
			"📈 System Load: %s\n"+
			"📋 RAM: %s\n"+
			"🔹 TCP: %d\n"+
			"🔸 UDP: %d\n"+
			"🚦 Traffic: %s (↑%s,↓%s)\n"+
			"ℹ️ Status: %s",
		constant.Version, strings.Title(cfg.CoreType), coreVersion, ipv4, ipv6, uptime, loadAverage, memoryUsage, tcpCount, udpCount, totalTraffic, uploadTraffic, downloadTraffic, serviceStatus,
	)

	if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatID, message); err != nil {
		log.Printf("Error sending daily report to Telegram: %v", err)
	} else {
		log.Println("Daily report sent successfully to Telegram")
	}
}

// formatBytes converts bytes to a human-readable format.
func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	if bytes >= TB {
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	} else if bytes >= GB {
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	} else if bytes >= MB {
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	} else if bytes >= KB {
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	}
	return fmt.Sprintf("%d B", bytes)
}

// MonitorDailyReport schedules the daily report to run every 24 hours.
func MonitorDailyReport(ctx context.Context, memDB *sql.DB, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		SendDailyReport(memDB, cfg)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				SendDailyReport(memDB, cfg)
			case <-ctx.Done():
				return
			}
		}
	}()
}

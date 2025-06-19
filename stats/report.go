package stats

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"strings"
	"os/exec"
	"path/filepath"

	"v2ray-stat/config"
	"v2ray-stat/telegram"
)

func getXrayVersion(cfg *config.Config) string {
	xrayPath := filepath.Join(cfg.CoreDir, "xray")
	cmd := exec.Command(xrayPath, "version")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Ошибка получения версии Xray: %v", err)
		return "unknown"
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "unknown"
}

// SendDailyReport sends a daily Telegram notification with system and network stats.
func SendDailyReport(memDB *sql.DB, cfg *config.Config) {
	if cfg.TelegramBotToken == "" || cfg.TelegramChatId == "" {
		log.Println("Отправка ежедневного отчета невозможна: отсутствует TelegramBotToken или TelegramChatId")
		return
	}

	xrayVersion := getXrayVersion(cfg)
	ipv4, ipv6 := getIPAddresses()
	uptime := GetUptime()
	loadAverage := GetLoadAverage()
	memoryUsage := GetMemoryUsage()
	tcpCount, udpCount := getConnectionCounts()

	var uplink, downlink uint64
	err := memDB.QueryRow("SELECT uplink, downlink FROM traffic_stats WHERE source = 'direct'").Scan(&uplink, &downlink)
	if err != nil {
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
		"📡 Xray Version: %s\n"+
		"🌐 IPv4: %s\n"+
		"🌐 IPv6: %s\n"+
		"⏳ Uptime: %s\n"+
		"📈 System Load: %s\n"+
		"📋 RAM: %s\n"+
		"🔹 TCP: %d\n"+
		"🔸 UDP: %d\n"+
		"🚦 Traffic: %s (↑%s,↓%s)\n"+
		"ℹ️ Status: %s",
		xrayVersion, ipv4, ipv6, uptime, loadAverage, memoryUsage, tcpCount, udpCount, totalTraffic, uploadTraffic, downloadTraffic, serviceStatus,
	)

	if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatId, message); err != nil {
		log.Printf("Ошибка отправки ежедневного отчета: %v", err)
	} else {
		log.Println("Ежедневный отчет успешно отправлен")
	}
}

// getIPAddresses returns the system's IPv4 and IPv6 addresses.
func getIPAddresses() (ipv4, ipv6 string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Ошибка получения IP-адресов: %v", err)
		return "unknown", "unknown"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ipv4 = ipNet.IP.String()
			} else if ipNet.IP.To16() != nil {
				ipv6 = ipNet.IP.String()
			}
		}
	}

	if ipv4 == "" {
		ipv4 = "none"
	}
	if ipv6 == "" {
		ipv6 = "none"
	}
	return ipv4, ipv6
}

// getConnectionCounts returns the number of TCP and UDP connections (placeholder).
func getConnectionCounts() (tcpCount, udpCount int) {
    tcpData, err := os.ReadFile("/proc/net/tcp")
    if err == nil {
        tcpLines := strings.Split(string(tcpData), "\n")
        tcpCount = len(tcpLines)
    }
    udpData, err := os.ReadFile("/proc/net/udp")
    if err == nil {
        udpLines := strings.Split(string(udpData), "\n")
        udpCount = len(udpLines)
    }
    return tcpCount, udpCount
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
	// Проверяем наличие конфигурации Telegram
	if cfg.TelegramBotToken == "" || cfg.TelegramChatId == "" {
		log.Println("Рутина ежедневного отчета не запущена: отсутствует TelegramBotToken или TelegramChatId")
		return
	}

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
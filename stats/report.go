package stats

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/constant"
	"v2ray-stat/telegram"
)

func getCoreVersion(cfg *config.Config) string {
	var binaryName string
	switch cfg.CoreType {
	case "xray":
		binaryName = "xray"
	case "singbox":
		binaryName = "sing-box"
	}

	binaryPath := filepath.Join(cfg.CoreDir, binaryName)
	cmd := exec.Command(binaryPath, "version")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error retrieving %s version: %v", cfg.CoreType, err)
		return "unknown"
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if cfg.CoreType == "xray" && len(parts) >= 2 {
			return parts[1] // Xray version is the second field (e.g., 25.3.6)
		} else if cfg.CoreType == "singbox" && len(parts) >= 3 {
			return parts[2] // Singbox version is the third field (e.g., 1.11.13)
		}
	}
	log.Printf("Error: invalid version output for %s", cfg.CoreType)
	return "unknown"
}

// SendDailyReport sends a daily Telegram notification with system and network stats.
func SendDailyReport(memDB *sql.DB, cfg *config.Config) {
	if cfg.TelegramBotToken == "" || cfg.TelegramChatId == "" {
		log.Println("Error: cannot send daily report: TelegramBotToken or TelegramChatId is missing")
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

	if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatId, message); err != nil {
		log.Printf("Error sending daily report to Telegram: %v", err)
	} else {
		log.Println("Daily report sent successfully to Telegram")
	}
}

// getIPAddresses returns the system's IPv4 and IPv6 addresses.
func getIPAddresses() (ipv4, ipv6 string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Error retrieving IP addresses: %v", err)
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
	if err != nil {
		log.Printf("Error reading /proc/net/tcp: %v", err)
	} else {
		tcpLines := strings.Split(string(tcpData), "\n")
		tcpCount = len(tcpLines) - 1 // Subtract header line
	}

	udpData, err := os.ReadFile("/proc/net/udp")
	if err != nil {
		log.Printf("Error reading /proc/net/udp: %v", err)
	} else {
		udpLines := strings.Split(string(udpData), "\n")
		udpCount = len(udpLines) - 1 // Subtract header line
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
	if cfg.TelegramBotToken == "" || cfg.TelegramChatId == "" {
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
				log.Println("Daily report routine stopped")
				return
			}
		}
	}()
}

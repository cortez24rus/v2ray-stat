package stats

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/telegram"
)

var (
	serviceStatuses   = make(map[string]bool)
	isFirstCheck      = true
	statusMutex       sync.Mutex
	diskMutex         sync.Mutex
	memoryMutex       sync.Mutex
	diskExceeded      bool
	memoryExceeded    bool
	diskPercentages   []float64
	memoryPercentages []float64
)

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

// isServiceRunning returns true if a process with the name svc is found in /proc
func isServiceRunning(svc string) bool {
	procDir, err := os.Open("/proc")
	if err != nil {
		log.Printf("Error opening /proc for service %s: %v", svc, err)
		return false
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		log.Printf("Error reading /proc for service %s: %v", svc, err)
		return false
	}

	for _, entry := range entries {
		if _, err := strconv.Atoi(entry); err != nil {
			continue
		}
		commPath := filepath.Join("/proc", entry, "comm")
		commData, err := os.ReadFile(commPath)
		if err != nil {
			log.Printf("Error reading %s for service %s: %v", commPath, svc, err)
			continue
		}
		if strings.TrimSpace(string(commData)) == svc {
			return true
		}
	}
	return false
}

// CheckServiceStatus checks service statuses and sends a notification if something changes
func CheckServiceStatus(token, chatID string, services []string) {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	var changed []string
	var statusLines []string

	for _, svc := range services {
		running := isServiceRunning(svc)
		prev, seen := serviceStatuses[svc]

		if !isFirstCheck && seen && prev != running {
			changed = append(changed, svc)
		}

		serviceStatuses[svc] = running
		state := "▼"
		if running {
			state = "▲"
		}
		statusLines = append(statusLines, fmt.Sprintf("%s %s", state, svc))
	}

	if !isFirstCheck && len(changed) > 0 {
		msg := fmt.Sprintf("⚠️ Service Status Update:\n%s", strings.Join(statusLines, "\n"))
		if err := telegram.SendNotification(token, chatID, msg); err != nil {
			log.Printf("Error sending service status notification: %v", err)
		} else {
			log.Println("Service status notification sent successfully")
		}
	}

	if isFirstCheck {
		isFirstCheck = false
	}
}

// GetUptime returns the system uptime
func GetUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		log.Printf("Error reading /proc/uptime: %v", err)
		return "unknown"
	}
	var uptimeSeconds float64
	fmt.Sscanf(string(data), "%f", &uptimeSeconds)

	days := int(uptimeSeconds / (24 * 3600))
	hours := int(uptimeSeconds/3600) % 24

	return fmt.Sprintf("%d days %02d hours", days, hours)
}

// GetLoadAverage returns the system load average
func GetLoadAverage() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		log.Printf("Error reading /proc/loadavg: %v", err)
		return "unknown"
	}
	var load1, load5, load15 float64
	fmt.Sscanf(string(data), "%f %f %f", &load1, &load5, &load15)
	return fmt.Sprintf("%.2f, %.2f, %.2f", load1, load5, load15)
}

// GetMemoryUsage returns memory usage information without sending notifications
func GetMemoryUsage() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		log.Printf("Error reading /proc/meminfo: %v", err)
		return "unknown"
	}

	var memTotal, memAvailable uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "MemTotal:" {
			memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
		}
		if fields[0] == "MemAvailable:" {
			memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	if memTotal == 0 {
		log.Printf("Invalid memory data: MemTotal is zero")
		return "unknown"
	}

	usedMem := memTotal - memAvailable
	return fmt.Sprintf("%.2f MB used / %.2f MB total",
		float64(usedMem)/(1024), float64(memTotal)/(1024))
}

// CheckMemoryUsage checks memory usage and sends notifications if thresholds are exceeded
func CheckMemoryUsage(token string, chatID string, threshold int, interval int) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		log.Printf("Error reading /proc/meminfo: %v", err)
		return
	}

	var memTotal, memAvailable uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "MemTotal:" {
			memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
		}
		if fields[0] == "MemAvailable:" {
			memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	if memTotal == 0 {
		log.Printf("Invalid memory data: MemTotal is zero")
		return
	}

	usedMem := memTotal - memAvailable
	percentage := float64(usedMem) / float64(memTotal) * 100

	memoryMutex.Lock()
	defer memoryMutex.Unlock()

	const tickInterval = 10
	measurements := (interval + tickInterval - 1) / tickInterval
	if measurements < 1 {
		measurements = 1
	}

	memoryPercentages = append(memoryPercentages, percentage)
	if len(memoryPercentages) > measurements {
		memoryPercentages = memoryPercentages[1:]
	}

	if len(memoryPercentages) == measurements {
		var sum float64
		for _, p := range memoryPercentages {
			sum += p
		}
		average := sum / float64(len(memoryPercentages))

		if average > float64(threshold) && !memoryExceeded {
			message := fmt.Sprintf("🚨 ALERT: Average memory usage over *%d* seconds exceeded *%d%%*! (Current: *%.2f%%*)", interval, threshold, average)
			if err := telegram.SendNotification(token, chatID, message); err != nil {
				log.Printf("Error sending memory usage notification to Telegram: %v", err)
			} else {
				log.Println("Memory usage notification sent successfully to Telegram")
			}
			memoryExceeded = true
		} else if average <= float64(threshold) && memoryExceeded {
			message := fmt.Sprintf("✅ Average memory usage over *%d* seconds dropped below *%d%%*. (Current: *%.2f%%*)", interval, threshold, average)
			if err := telegram.SendNotification(token, chatID, message); err != nil {
				log.Printf("Error sending memory usage notification to Telegram: %v", err)
			} else {
				log.Println("Memory usage notification sent successfully to Telegram")
			}
			memoryExceeded = false
		}
	}
}

// GetDiskUsage returns disk usage information without sending notifications
func GetDiskUsage() string {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		log.Printf("Error getting disk usage: %v", err)
		return "unknown"
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free

	if total == 0 {
		log.Printf("Invalid disk data: total size is zero")
		return "unknown"
	}

	return fmt.Sprintf("%.2f GB used / %.2f GB total",
		float64(used)/(1024*1024*1024), float64(total)/(1024*1024*1024))
}

// CheckDiskUsage checks disk usage and sends notifications if thresholds are exceeded
func CheckDiskUsage(token string, chatID string, threshold int, interval int) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		log.Printf("Error getting disk usage: %v", err)
		return
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free

	if total == 0 {
		log.Printf("Invalid disk data: total size is zero")
		return
	}

	percentage := float64(used) / float64(total) * 100

	diskMutex.Lock()
	defer diskMutex.Unlock()

	const tickInterval = 10
	measurements := (interval + tickInterval - 1) / tickInterval
	if measurements < 1 {
		measurements = 1
	}

	diskPercentages = append(diskPercentages, percentage)
	if len(diskPercentages) > measurements {
		diskPercentages = diskPercentages[1:]
	}

	if len(diskPercentages) == measurements {
		var sum float64
		for _, p := range diskPercentages {
			sum += p
		}
		average := sum / float64(len(diskPercentages))

		if average > float64(threshold) && !diskExceeded {
			message := fmt.Sprintf("🚨 ALERT: Average disk usage over *%d* seconds exceeded *%d%%*! (Current: *%.2f%%*)", interval, threshold, average)
			if err := telegram.SendNotification(token, chatID, message); err != nil {
				log.Printf("Error sending disk usage notification to Telegram: %v", err)
			} else {
				log.Println("Disk usage notification sent successfully to Telegram")
			}
			diskExceeded = true
		} else if average <= float64(threshold) && diskExceeded {
			message := fmt.Sprintf("✅ Average disk usage over *%d* seconds dropped below *%d%%*. (Current: *%.2f%%*)", interval, threshold, average)
			if err := telegram.SendNotification(token, chatID, message); err != nil {
				log.Printf("Error sending disk usage notification to Telegram: %v", err)
			} else {
				log.Println("Disk usage notification sent successfully to Telegram")
			}
			diskExceeded = false
		}
	}
}

// GetStatus returns the status of specified services without sending notifications
func GetStatus(services []string) string {
	var status strings.Builder

	statusMutex.Lock()
	defer statusMutex.Unlock()

	for _, svc := range services {
		isRunning := false
		procDir, err := os.Open("/proc")
		if err != nil {
			log.Printf("Error opening /proc for service %s: %v", svc, err)
			continue
		}
		defer procDir.Close()
		entries, err := procDir.Readdirnames(-1)
		if err != nil {
			log.Printf("Error reading /proc for service %s: %v", svc, err)
			continue
		}
		for _, entry := range entries {
			if _, err := strconv.Atoi(entry); err == nil {
				commPath := filepath.Join("/proc", entry, "comm")
				commData, err := os.ReadFile(commPath)
				if err != nil {
					log.Printf("Error reading %s for service %s: %v", commPath, svc, err)
					continue
				}
				comm := strings.TrimSpace(string(commData))
				if comm == svc {
					isRunning = true
					break
				}
			}
		}

		serviceStatuses[svc] = isRunning

		state := "▼"
		if isRunning {
			state = "▲"
		}
		fmt.Fprintf(&status, "%s %s ", state, svc)
	}

	return strings.TrimSpace(status.String())
}

func MonitorStats(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				CheckServiceStatus(cfg.TelegramBotToken, cfg.TelegramChatID, cfg.Services)
				CheckDiskUsage(cfg.TelegramBotToken, cfg.TelegramChatID, cfg.DiskThreshold, cfg.MemoryAverageInterval)
				CheckMemoryUsage(cfg.TelegramBotToken, cfg.TelegramChatID, cfg.MemoryThreshold, cfg.MemoryAverageInterval)
			case <-ctx.Done():
				return
			}
		}
	}()
}

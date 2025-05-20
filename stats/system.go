package stats

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	serviceStatuses   = make(map[string]bool)
	statusMutex       sync.Mutex
	isFirstCheck      = true
	memoryExceeded    bool
	memoryMutex       sync.Mutex
	memoryPercentages []float64
	diskExceeded      bool
	diskMutex         sync.Mutex
	diskPercentages   []float64
)

// GetUptime returns the system uptime
func GetUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
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
		return "unknown"
	}
	var load1, load5, load15 float64
	fmt.Sscanf(string(data), "%f %f %f", &load1, &load5, &load15)
	return fmt.Sprintf("%.2f, %.2f, %.2f", load1, load5, load15)
}

// GetMemoryUsage returns memory usage information
func GetMemoryUsage(token string, chatID string, sendNotification func(string, string, string) error, threshold int, interval int) string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "unknown"
	}

	var memTotal, memAvailable uint64
	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
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
		return "unknown"
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
			message := fmt.Sprintf("🚨 ALERT: Average memory usage over %d seconds exceeded %d%%! (Current: %.2f%%)", interval, threshold, average)
			if err := sendNotification(token, chatID, message); err != nil {
				log.Printf("Failed to send memory alert: %v", err)
			}
			memoryExceeded = true
		} else if average <= float64(threshold) && memoryExceeded {
			message := fmt.Sprintf("✅ Average memory usage over %d seconds dropped below %d%%. (Current: %.2f%%)", interval, threshold, average)
			if err := sendNotification(token, chatID, message); err != nil {
				log.Printf("Failed to send memory recovery notification: %v", err)
			}
			memoryExceeded = false
		}
	}

	return fmt.Sprintf("%.2f MB used / %.2f MB total",
		float64(usedMem)/(1024), float64(memTotal)/(1024))
}

// GetDiskUsage returns disk usage information
func GetDiskUsage(token string, chatID string, sendNotification func(string, string, string) error, threshold int, interval int) string {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return "unknown"
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free

	if total == 0 {
		return "unknown"
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
			message := fmt.Sprintf("🚨 ALERT: Average disk usage over %d seconds exceeded %d%%! (Current: %.2f%%)", interval, threshold, average)
			if err := sendNotification(token, chatID, message); err != nil {
				log.Printf("Failed to send disk alert: %v", err)
			}
			diskExceeded = true
		} else if average <= float64(threshold) && diskExceeded {
			message := fmt.Sprintf("✅ Average disk usage over %d seconds dropped below %d%%. (Current: %.2f%%)", interval, threshold, average)
			if err := sendNotification(token, chatID, message); err != nil {
				log.Printf("Failed to send disk recovery notification: %v", err)
			}
			diskExceeded = false
		}
	}

	return fmt.Sprintf("%.2f GB used / %.2f GB total",
		float64(used)/(1024*1024*1024), float64(total)/(1024*1024*1024))
}

// GetStatus returns the status of specified services
func GetStatus(services []string, token, chatID string, sendNotification func(string, string, string) error) string {
	var status strings.Builder
	var changedServices []string
	var statusMessages []string

	statusMutex.Lock()
	defer statusMutex.Unlock()

	for _, svc := range services {
		isRunning := false
		procDir, err := os.Open("/proc")
		if err == nil {
			defer procDir.Close()
			entries, err := procDir.Readdirnames(-1)
			if err == nil {
				for _, entry := range entries {
					if _, err := strconv.Atoi(entry); err == nil {
						commPath := filepath.Join("/proc", entry, "comm")
						commData, err := os.ReadFile(commPath)
						if err == nil {
							comm := strings.TrimSpace(string(commData))
							if comm == svc {
								isRunning = true
								break
							}
						}
					}
				}
			}
		}

		if !isFirstCheck {
			previousStatus, exists := serviceStatuses[svc]
			if exists && previousStatus != isRunning {
				changedServices = append(changedServices, svc)
			}
		}

		serviceStatuses[svc] = isRunning

		state := "▼"
		if isRunning {
			state = "▲"
		}
		fmt.Fprintf(&status, "%s %s ", state, svc)
		statusMessages = append(statusMessages, fmt.Sprintf("%s %s", state, svc))
	}

	if !isFirstCheck && len(changedServices) > 0 {
		message := fmt.Sprintf("⚠️ Service Status Update:\n%s", strings.Join(statusMessages, "\n"))
		if err := sendNotification(token, chatID, message); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to send Telegram notification: %v\n", err)
		}
	}

	if isFirstCheck {
		isFirstCheck = false
	}

	return strings.TrimSpace(status.String())
}

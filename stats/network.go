package stats

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// NetworkStats holds network interface statistics
type NetworkStats struct {
	RxBytes, TxBytes     uint64
	RxPackets, TxPackets uint64
}

// TrafficMonitor monitors network traffic for a specified interface
type TrafficMonitor struct {
	Iface           string
	mu              sync.RWMutex
	rxSpeed         float64
	txSpeed         float64
	rxPacketsPerSec float64
	txPacketsPerSec float64
	totalRxBytes    uint64
	totalTxBytes    uint64
	initialRxBytes  uint64
	initialTxBytes  uint64
	lastStats       NetworkStats
	lastUpdate      time.Time
	isFirstUpdate   bool
}

// NewTrafficMonitor creates a new TrafficMonitor and stores initial statistics
func NewTrafficMonitor(iface string) (*TrafficMonitor, error) {
	initialStats, err := readNetworkStats(iface)
	if err != nil {
		log.Printf("Error initializing traffic monitor: %v", err)
		return nil, fmt.Errorf("failed to initialize traffic monitor: %v", err)
	}

	return &TrafficMonitor{
		Iface:          iface,
		initialRxBytes: initialStats.RxBytes,
		initialTxBytes: initialStats.TxBytes,
		lastStats:      initialStats,
		isFirstUpdate:  true,
	}, nil
}

// UpdateStats updates network traffic statistics for one iteration
func (tm *TrafficMonitor) UpdateStats() error {
	stats, err := readNetworkStats(tm.Iface)
	if err != nil {
		log.Printf("Error updating network stats: %v", err)
		return fmt.Errorf("failed to update network stats: %v", err)
	}

	currentTime := time.Now()
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if !tm.isFirstUpdate {
		deltaTime := currentTime.Sub(tm.lastUpdate).Seconds()
		if deltaTime > 0 {
			tm.rxSpeed = float64((stats.RxBytes-tm.lastStats.RxBytes)*8) / deltaTime
			tm.txSpeed = float64((stats.TxBytes-tm.lastStats.TxBytes)*8) / deltaTime
			tm.rxPacketsPerSec = float64(stats.RxPackets-tm.lastStats.RxPackets) / deltaTime
			tm.txPacketsPerSec = float64(stats.TxPackets-tm.lastStats.TxPackets) / deltaTime
			tm.totalRxBytes = stats.RxBytes - tm.initialRxBytes
			tm.totalTxBytes = stats.TxBytes - tm.initialTxBytes
		}
	} else {
		tm.totalRxBytes = 0
		tm.totalTxBytes = 0
		tm.isFirstUpdate = false
	}

	tm.lastStats = stats
	tm.lastUpdate = currentTime
	return nil
}

// ResetTraffic resets accumulated traffic by updating initial values
func (tm *TrafficMonitor) ResetTraffic() error {
	stats, err := readNetworkStats(tm.Iface)
	if err != nil {
		log.Printf("Error resetting traffic: %v", err)
		return fmt.Errorf("failed to reset traffic: %v", err)
	}

	tm.mu.Lock()
	tm.initialRxBytes = stats.RxBytes
	tm.initialTxBytes = stats.TxBytes
	tm.totalRxBytes = 0
	tm.totalTxBytes = 0
	tm.mu.Unlock()

	return nil
}

// GetStats returns current network statistics
func (tm *TrafficMonitor) GetStats() (rxSpeed, txSpeed, rxPacketsPerSec, txPacketsPerSec float64, totalRxBytes, totalTxBytes uint64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.rxSpeed, tm.txSpeed, tm.rxPacketsPerSec, tm.txPacketsPerSec, tm.totalRxBytes, tm.totalTxBytes
}

func readNetworkStats(iface string) (NetworkStats, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		log.Printf("Error reading /proc/net/dev: %v", err)
		return NetworkStats{}, fmt.Errorf("failed to read /proc/net/dev: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, iface+":") {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				log.Printf("Invalid data format for interface %s", iface)
				return NetworkStats{}, fmt.Errorf("invalid data format for interface %s", iface)
			}

			var stats NetworkStats
			_, err := fmt.Sscanf(fields[1], "%d", &stats.RxBytes)
			if err != nil {
				log.Printf("Error parsing rx bytes for interface %s: %v", iface, err)
				return NetworkStats{}, fmt.Errorf("failed to parse rx bytes: %v", err)
			}
			_, err = fmt.Sscanf(fields[2], "%d", &stats.RxPackets)
			if err != nil {
				log.Printf("Error parsing rx packets for interface %s: %v", iface, err)
				return NetworkStats{}, fmt.Errorf("failed to parse rx packets: %v", err)
			}
			_, err = fmt.Sscanf(fields[9], "%d", &stats.TxBytes)
			if err != nil {
				log.Printf("Error parsing tx bytes for interface %s: %v", iface, err)
				return NetworkStats{}, fmt.Errorf("failed to parse tx bytes: %v", err)
			}
			_, err = fmt.Sscanf(fields[10], "%d", &stats.TxPackets)
			if err != nil {
				log.Printf("Error parsing tx packets for interface %s: %v", iface, err)
				return NetworkStats{}, fmt.Errorf("failed to parse tx packets: %v", err)
			}
			return stats, nil
		}
	}
	log.Printf("Interface %s not found in /proc/net/dev", iface)
	return NetworkStats{}, fmt.Errorf("interface %s not found", iface)
}

// FormatTraffic formats traffic volume in human-readable units
func FormatTraffic(bytes uint64) string {
	const (
		kb = 1024
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	if bytes >= gb {
		return fmt.Sprintf("%.2f GB", float64(bytes)/gb)
	} else if bytes >= mb {
		return fmt.Sprintf("%.2f MB", float64(bytes)/mb)
	} else if bytes >= kb {
		return fmt.Sprintf("%.2f KB", float64(bytes)/kb)
	}
	return fmt.Sprintf("%d B", bytes)
}

// Запуск мониторинга сети
func MonitorNetworkRoutine(ctx context.Context, wg *sync.WaitGroup) {
	trafficMonitor := GetTrafficMonitor()
	if trafficMonitor == nil {
		log.Println("Network monitoring not initialized, skipping routine")
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := trafficMonitor.UpdateStats(); err != nil {
					log.Printf("Error updating network stats for interface %s: %v", trafficMonitor.Iface, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

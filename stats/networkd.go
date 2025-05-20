package stats

import (
	"fmt"
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
	stopChan        chan struct{}
}

// NewTrafficMonitor creates a new TrafficMonitor and stores initial statistics
func NewTrafficMonitor(iface string) (*TrafficMonitor, error) {
	initialStats, err := readNetworkStats(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize traffic monitor: %v", err)
	}

	return &TrafficMonitor{
		Iface:          iface,
		initialRxBytes: initialStats.RxBytes,
		initialTxBytes: initialStats.TxBytes,
		stopChan:       make(chan struct{}),
	}, nil
}

func (tm *TrafficMonitor) Start() {
	var prevStats NetworkStats
	var prevTime time.Time
	firstRun := true

	for {
		select {
		case <-tm.stopChan:
			return
		default:
			stats, err := readNetworkStats(tm.Iface)
			if err != nil {
				time.Sleep(10 * time.Second)
				continue
			}

			currentTime := time.Now()
			if !firstRun {
				deltaTime := currentTime.Sub(prevTime).Seconds()
				if deltaTime > 0 {
					rxBitsPerSec := float64((stats.RxBytes-prevStats.RxBytes)*8) / deltaTime
					txBitsPerSec := float64((stats.TxBytes-prevStats.TxBytes)*8) / deltaTime
					rxPacketsPerSec := float64(stats.RxPackets-prevStats.RxPackets) / deltaTime
					txPacketsPerSec := float64(stats.TxPackets-prevStats.TxPackets) / deltaTime

					tm.mu.Lock()
					tm.rxSpeed = rxBitsPerSec
					tm.txSpeed = txBitsPerSec
					tm.rxPacketsPerSec = rxPacketsPerSec
					tm.txPacketsPerSec = txPacketsPerSec

					tm.totalRxBytes = stats.RxBytes - tm.initialRxBytes
					tm.totalTxBytes = stats.TxBytes - tm.initialTxBytes
					tm.mu.Unlock()
				}
			} else {
				tm.mu.Lock()
				tm.totalRxBytes = 0
				tm.totalTxBytes = 0
				tm.mu.Unlock()
			}

			prevStats = stats
			prevTime = currentTime
			firstRun = false

			time.Sleep(10 * time.Second)
		}
	}
}

// ResetTraffic resets accumulated traffic by updating initial values
func (tm *TrafficMonitor) ResetTraffic() error {
	stats, err := readNetworkStats(tm.Iface)
	if err != nil {
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

func (tm *TrafficMonitor) Stop() {
	close(tm.stopChan)
}

func (tm *TrafficMonitor) GetStats() (rxSpeed, txSpeed, rxPacketsPerSec, txPacketsPerSec float64, totalRxBytes, totalTxBytes uint64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.rxSpeed, tm.txSpeed, tm.rxPacketsPerSec, tm.txPacketsPerSec, tm.totalRxBytes, tm.totalTxBytes
}

func readNetworkStats(iface string) (NetworkStats, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return NetworkStats{}, fmt.Errorf("failed to read /proc/net/dev: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, iface+":") {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				return NetworkStats{}, fmt.Errorf("invalid data format for interface %s", iface)
			}

			var stats NetworkStats
			_, err := fmt.Sscanf(fields[1], "%d", &stats.RxBytes)
			if err != nil {
				return NetworkStats{}, fmt.Errorf("failed to parse rx bytes: %v", err)
			}
			_, err = fmt.Sscanf(fields[2], "%d", &stats.RxPackets)
			if err != nil {
				return NetworkStats{}, fmt.Errorf("failed to parse rx packets: %v", err)
			}
			_, err = fmt.Sscanf(fields[9], "%d", &stats.TxBytes)
			if err != nil {
				return NetworkStats{}, fmt.Errorf("failed to parse tx bytes: %v", err)
			}
			_, err = fmt.Sscanf(fields[10], "%d", &stats.TxPackets)
			if err != nil {
				return NetworkStats{}, fmt.Errorf("failed to parse tx packets: %v", err)
			}
			return stats, nil
		}
	}
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

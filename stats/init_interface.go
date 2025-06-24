package stats

import (
	"fmt"
	"log"
	"net"
)

var trafficMonitor *TrafficMonitor

func setTrafficMonitor(tm *TrafficMonitor) {
	trafficMonitor = tm
}

func GetTrafficMonitor() *TrafficMonitor {
	return trafficMonitor
}

func GetDefaultInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	count := 0
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}

		count++
		if count == 2 {
			return i.Name, nil
		}
	}

	return "", fmt.Errorf("second active interface not found")
}

// Инициализация мониторинга сети
func InitNetworkMonitoring() error {
	iface, err := GetDefaultInterface()
	if err != nil {
		log.Printf("Error determining default network interface: %v", err)
		return fmt.Errorf("failed to determine default network interface: %v", err)
	}

	monitor, err := NewTrafficMonitor(iface)
	if err != nil {
		log.Printf("Error initializing traffic monitor for interface %s: %v", iface, err)
		return fmt.Errorf("failed to initialize traffic monitor for interface %s: %v", iface, err)
	}

	// Сохраняем монитор в пакете stats для дальнейшего использования
	setTrafficMonitor(monitor)
	log.Printf("Network monitoring initialized for interface %s", iface)
	return nil
}

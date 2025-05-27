package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the configuration settings for the application.
type Config struct {
	ProxyType             string
	DatabasePath          string
	ProxyDir              string
	LuaFilePath           string
	XipLogFile            string
	BannedLogFile         string
	IpTtl                 time.Duration
	Port                  string
	TelegramBotToken      string
	TelegramChatId        string
	Services              []string
	MemoryAverageInterval int
	DiskThreshold         int
	MemoryThreshold       int
}

// defaultConfig provides default configuration values.
var defaultConfig = Config{
	ProxyType:             "xray",
	DatabasePath:          "/usr/local/xcore/data.db",
	ProxyDir:              "/usr/local/etc/xray/",
	LuaFilePath:           "/etc/haproxy/.auth.lua",
	XipLogFile:            "/var/log/xcore.log",
	BannedLogFile:         "/var/log/xcore-banned.log",
	Port:                  "9952",
	IpTtl:                 66 * time.Second,
	TelegramBotToken:      "",
	TelegramChatId:        "",
	Services:              []string{"xray", "haproxy", "nginx", "fail2ban-server"},
	MemoryAverageInterval: 120,
	DiskThreshold:         0,
	MemoryThreshold:       0,
}

// LoadConfig reads configuration from the specified file and returns a Config struct.
func LoadConfig(configFile string) (Config, error) {
	cfg := defaultConfig

	file, err := os.Open(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Configuration file %s not found, using default values", configFile)
			return cfg, nil
		}
		return cfg, fmt.Errorf("error opening configuration file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	configMap := make(map[string]string)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: invalid line in configuration: %s", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		configMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return cfg, fmt.Errorf("error reading configuration file: %v", err)
	}

	if val, ok := configMap["DATABASE_PATH"]; ok && val != "" {
		cfg.DatabasePath = val
	}
	if val, ok := configMap["PROXY_DIR"]; ok && val != "" {
		cfg.ProxyDir = val
	}
	if val, ok := configMap["LUA_FILE_PATH"]; ok && val != "" {
		cfg.LuaFilePath = val
	}
	if val, ok := configMap["XIP_LOG_FILE"]; ok && val != "" {
		cfg.XipLogFile = val
	}
	if val, ok := configMap["BANNED_LOG_FILE"]; ok && val != "" {
		cfg.BannedLogFile = val
	}
	if val, ok := configMap["PORT"]; ok && val != "" {
		portNum, err := strconv.Atoi(val)
		if err != nil || portNum < 1 || portNum > 65535 {
			return cfg, fmt.Errorf("invalid port: %s", val)
		}
		cfg.Port = val
	}
	if val, ok := configMap["TELEGRAM_BOT_TOKEN"]; ok && val != "" {
		cfg.TelegramBotToken = val
	}
	if val, ok := configMap["TELEGRAM_CHAT_ID"]; ok && val != "" {
		cfg.TelegramChatId = val
	}
	if val, ok := configMap["SERVICES"]; ok && val != "" {
		cfg.Services = strings.Split(val, ",")
		for i, svc := range cfg.Services {
			cfg.Services[i] = strings.TrimSpace(svc)
		}
	}
	if val, ok := configMap["MEMORY_AVERAGE_INTERVAL"]; ok {
		interval, _ := strconv.Atoi(val)
		if interval < 10 {
			log.Printf("Invalid MEMORY_AVERAGE_INTERVAL value, using default: %d", cfg.MemoryAverageInterval)
		} else {
			cfg.MemoryAverageInterval = interval
		}
	}
	if val, ok := configMap["MEMORY_THRESHOLD"]; ok {
		mthreshold, _ := strconv.Atoi(val)
		if mthreshold < 0 || mthreshold > 100 {
			log.Printf("Invalid MEMORY_THRESHOLD value '%s', using default %d%%", val, cfg.MemoryThreshold)
		} else {
			cfg.MemoryThreshold = mthreshold
		}
	}
	if val, ok := configMap["DISK_THRESHOLD"]; ok {
		dthreshold, _ := strconv.Atoi(val)
		if dthreshold < 0 || dthreshold > 100 {
			log.Printf("Invalid DISK_THRESHOLD value '%s', using default %d%%", val, cfg.DiskThreshold)
		} else {
			cfg.DiskThreshold = dthreshold
		}
	}
	if val, ok := configMap["PROXY_TYPE"]; ok {
		if val == "xray" || val == "singbox" {
			cfg.ProxyType = val
		}
	}

	return cfg, nil
}

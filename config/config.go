package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds the configuration settings for the application.
type Config struct {
	CoreType              string
	Port                  string
	CoreDir               string
	CoreConfig            string
	DatabasePath          string
	V2LogFile             string
	BannedLogFile         string
	AuthLuaPath           string
	AccessLogPath         string
	AccessLogRegex        string
	IpTtl                 time.Duration
	TelegramBotToken      string
	TelegramChatID        string
	Services              []string
	MemoryAverageInterval int
	DiskThreshold         int
	MemoryThreshold       int
	Features              map[string]bool
	MonitorTickerInterval int
	APIToken              string
}

// defaultConfig provides default configuration values.
var defaultConfig = Config{
	CoreType:              "xray",
	Port:                  "9952",
	CoreDir:               "/usr/local/etc/xray/",
	CoreConfig:            "/usr/local/etc/xray/config.json",
	DatabasePath:          "/usr/local/v2ray-stat/data.db",
	V2LogFile:             "/var/log/v2ray-stat.log",
	BannedLogFile:         "/var/log/v2ray-stat-banned.log",
	AuthLuaPath:           "/etc/haproxy/.auth.lua",
	AccessLogPath:         "/usr/local/etc/xray/access.log",
	AccessLogRegex:        `from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`,
	IpTtl:                 66 * time.Second,
	TelegramBotToken:      "",
	TelegramChatID:        "",
	Services:              []string{"xray", "fail2ban-server"},
	MemoryAverageInterval: 120,
	DiskThreshold:         0,
	MemoryThreshold:       0,
	Features:              make(map[string]bool),
	MonitorTickerInterval: 10,
	APIToken:              "",
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

	for key, value := range configMap {
		switch key {
		case "CORE_TYPE":
			if value == "xray" || value == "singbox" {
				cfg.CoreType = value
			}
		case "CORE_DIR":
			if value != "" {
				cfg.CoreDir = value
			}
		case "CORE_CONFIG":
			if value != "" {
				cfg.CoreConfig = value
			}
		case "DATABASE_PATH":
			if value != "" {
				cfg.DatabasePath = value
			}
		case "V2_LOG_FILE":
			if value != "" {
				cfg.V2LogFile = value
			}
		case "BANNED_LOG_FILE":
			if value != "" {
				cfg.BannedLogFile = value
			}
		case "AUTH_LUA_PATH":
			if value != "" {
				cfg.AuthLuaPath = value
			}
		case "ACCESS_LOG_PATH":
			if value != "" {
				cfg.AccessLogPath = value
			}
		case "ACCESS_LOG_REGEX":
			if value != "" {
				if _, err := regexp.Compile(value); err != nil {
					log.Printf("Invalid ACCESS_LOG_REGEX from config file: %v, using default", err)
				} else {
					cfg.AccessLogRegex = value
				}
			}
		case "PORT":
			if value != "" {
				portNum, err := strconv.Atoi(value)
				if err != nil || portNum < 1 || portNum > 65535 {
					return cfg, fmt.Errorf("invalid port: %s", value)
				}
				cfg.Port = value
			}
		case "TELEGRAM_BOT_TOKEN":
			if value != "" {
				cfg.TelegramBotToken = value
			}
		case "TELEGRAM_CHAT_ID":
			if value != "" {
				cfg.TelegramChatID = value
			}
		case "SERVICES":
			if value != "" {
				cfg.Services = strings.Split(value, ",")
				for i, svc := range cfg.Services {
					cfg.Services[i] = strings.TrimSpace(svc)
				}
			}
		case "MEMORY_AVERAGE_INTERVAL":
			interval, err := strconv.Atoi(value)
			if err != nil || interval < 10 {
				log.Printf("Invalid MEMORY_AVERAGE_INTERVAL value, using default: %d", cfg.MemoryAverageInterval)
			} else {
				cfg.MemoryAverageInterval = interval
			}
		case "MEMORY_THRESHOLD":
			mthreshold, err := strconv.Atoi(value)
			if err != nil || mthreshold < 0 || mthreshold > 100 {
				log.Printf("Invalid MEMORY_THRESHOLD value '%s', using default %d%%", value, cfg.MemoryThreshold)
			} else {
				cfg.MemoryThreshold = mthreshold
			}
		case "DISK_THRESHOLD":
			dthreshold, err := strconv.Atoi(value)
			if err != nil || dthreshold < 0 || dthreshold > 100 {
				log.Printf("Invalid DISK_THRESHOLD value '%s', using default %d%%", value, cfg.DiskThreshold)
			} else {
				cfg.DiskThreshold = dthreshold
			}
		case "FEATURES":
			if value != "" {
				features := strings.Split(value, ",")
				for _, feature := range features {
					cfg.Features[strings.TrimSpace(feature)] = true
				}
			}
		case "MONITOR_TICKER_INTERVAL":
			interval, err := strconv.Atoi(value)
			if err != nil || interval < 1 {
				log.Printf("Invalid MONITOR_TICKER_INTERVAL value '%s', using default %d seconds", value, cfg.MonitorTickerInterval)
			} else {
				cfg.MonitorTickerInterval = interval
			}
		case "API_TOKEN":
			if value != "" {
				cfg.APIToken = value
			}
		default:
			log.Printf("Warning: unknown configuration key: %s", key)
		}
	}

	return cfg, nil
}

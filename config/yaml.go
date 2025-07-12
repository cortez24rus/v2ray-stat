package config

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration settings for the application.
type Config struct {
	Core             CoreConfig             `yaml:"core"`
	V2rayStat        V2rayStatConfig        `yaml:"v2ray-stat"`
	API              APIConfig              `yaml:"api"`
	Timezone         string                 `yaml:"timezone"`
	Features         map[string]bool        `yaml:"features"`
	Services         []string               `yaml:"services"`
	Telegram         TelegramConfig         `yaml:"telegram"`
	SystemMonitoring SystemMonitoringConfig `yaml:"system_monitoring"`
	Paths            PathsConfig            `yaml:"paths"`
	IpTtl            time.Duration          `yaml:"-"`
}

// CoreConfig holds core-related settings.
type CoreConfig struct {
	Dir            string `yaml:"dir"`
	Config         string `yaml:"config"`
	AccessLog      string `yaml:"access_log"`
	AccessLogRegex string `yaml:"access_log_regex"`
}

// V2rayStatConfig holds v2ray-stat specific settings.
type V2rayStatConfig struct {
	Type    string        `yaml:"type"`
	Port    string        `yaml:"port"`
	Monitor MonitorConfig `yaml:"monitor"`
}

// MonitorConfig holds monitoring-related settings.
type MonitorConfig struct {
	TickerInterval      int `yaml:"ticker_interval"`
	OnlineRateThreshold int `yaml:"online_rate_threshold"`
}

// APIConfig holds API-related settings.
type APIConfig struct {
	APIToken string `yaml:"api_token"`
}

// TelegramConfig holds Telegram notification settings.
type TelegramConfig struct {
	ChatID   string `yaml:"chat_id"`
	BotToken string `yaml:"bot_token"`
}

// SystemMonitoringConfig holds system monitoring settings.
type SystemMonitoringConfig struct {
	AverageInterval int          `yaml:"average_interval"`
	Memory          MemoryConfig `yaml:"memory"`
	Disk            DiskConfig   `yaml:"disk"`
}

// MemoryConfig holds memory monitoring settings.
type MemoryConfig struct {
	Threshold int `yaml:"threshold"`
}

// DiskConfig holds disk monitoring settings.
type DiskConfig struct {
	Threshold int `yaml:"threshold"`
}

// PathsConfig holds paths and logging settings.
type PathsConfig struct {
	Database     string `yaml:"database"`
	F2BLog       string `yaml:"f2b_log"`
	F2BBannedLog string `yaml:"f2b_banned_log"`
	AuthLua      string `yaml:"auth_lua"`
}

var defaultConfig = Config{
	Core: CoreConfig{
		Dir:            "/usr/local/etc/xray/",
		Config:         "/usr/local/etc/xray/config.json",
		AccessLog:      "/usr/local/etc/xray/access.log",
		AccessLogRegex: `from tcp:([0-9\.]+).*?tcp:([\w\.\-]+):\d+.*?email: (\S+)`,
	},
	V2rayStat: V2rayStatConfig{
		Type: "xray",
		Port: "9952",
		Monitor: MonitorConfig{
			TickerInterval:      10,
			OnlineRateThreshold: 0,
		},
	},
	API: APIConfig{
		APIToken: "",
	},
	Timezone: "",
	Features: make(map[string]bool),
	Services: []string{"xray", "fail2ban-server"},
	Telegram: TelegramConfig{
		ChatID:   "",
		BotToken: "",
	},
	SystemMonitoring: SystemMonitoringConfig{
		AverageInterval: 120,
		Memory: MemoryConfig{
			Threshold: 0,
		},
		Disk: DiskConfig{
			Threshold: 0,
		},
	},
	Paths: PathsConfig{
		Database:     "/usr/local/etc/v2ray-stat/data.db",
		F2BLog:       "/var/log/v2ray-stat.log ",
		F2BBannedLog: "/var/log/v2ray-stat-banned.log",
		AuthLua:      "/etc/haproxy/.auth.lua",
	},
}

// LoadConfig reads configuration from the specified YAML file and returns a Config struct.
func LoadConfig(configFile string) (Config, error) {
	cfg := defaultConfig

	// Read YAML file
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Configuration file %s not found, using default values", configFile)
			return cfg, nil
		}
		return cfg, fmt.Errorf("error reading configuration file: %v", err)
	}

	// Unmarshal YAML into Config struct
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("error parsing YAML configuration: %v", err)
	}

	// Validate and adjust configuration
	if cfg.V2rayStat.Type != "xray" && cfg.V2rayStat.Type != "singbox" {
		log.Printf("Invalid v2ray-stat.type '%s', using default: %s", cfg.V2rayStat.Type, defaultConfig.V2rayStat.Type)
		cfg.V2rayStat.Type = defaultConfig.V2rayStat.Type
	}

	if cfg.V2rayStat.Port != "" {
		portNum, err := strconv.Atoi(cfg.V2rayStat.Port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return cfg, fmt.Errorf("invalid v2ray-stat.port: %s", cfg.V2rayStat.Port)
		}
	}

	if cfg.Core.AccessLogRegex != "" {
		if _, err := regexp.Compile(cfg.Core.AccessLogRegex); err != nil {
			log.Printf("Invalid core.access_log_regex '%s', using default: %s", cfg.Core.AccessLogRegex, defaultConfig.Core.AccessLogRegex)
			cfg.Core.AccessLogRegex = defaultConfig.Core.AccessLogRegex
		}
	}

	if cfg.SystemMonitoring.AverageInterval < 10 {
		log.Printf("Invalid system_monitoring.average_interval value %d, using default: %d", cfg.SystemMonitoring.AverageInterval, defaultConfig.SystemMonitoring.AverageInterval)
		cfg.SystemMonitoring.AverageInterval = defaultConfig.SystemMonitoring.AverageInterval
	}

	if cfg.SystemMonitoring.Memory.Threshold < 0 || cfg.SystemMonitoring.Memory.Threshold > 100 {
		log.Printf("Invalid system_monitoring.memory.threshold value %d, using default: %d", cfg.SystemMonitoring.Memory.Threshold, defaultConfig.SystemMonitoring.Memory.Threshold)
		cfg.SystemMonitoring.Memory.Threshold = defaultConfig.SystemMonitoring.Memory.Threshold
	}

	if cfg.SystemMonitoring.Disk.Threshold < 0 || cfg.SystemMonitoring.Disk.Threshold > 100 {
		log.Printf("Invalid system_monitoring.disk.threshold value %d, using default: %d", cfg.SystemMonitoring.Disk.Threshold, defaultConfig.SystemMonitoring.Disk.Threshold)
		cfg.SystemMonitoring.Disk.Threshold = defaultConfig.SystemMonitoring.Disk.Threshold
	}

	if cfg.V2rayStat.Monitor.TickerInterval < 1 {
		log.Printf("Invalid v2ray-stat.monitor.ticker_interval value %d, using default: %d", cfg.V2rayStat.Monitor.TickerInterval, defaultConfig.V2rayStat.Monitor.TickerInterval)
		cfg.V2rayStat.Monitor.TickerInterval = defaultConfig.V2rayStat.Monitor.TickerInterval
	}

	if cfg.V2rayStat.Monitor.OnlineRateThreshold < 0 {
		log.Printf("Invalid v2ray-stat.monitor.online_rate_threshold value %d, using default: %d", cfg.V2rayStat.Monitor.OnlineRateThreshold, defaultConfig.V2rayStat.Monitor.OnlineRateThreshold)
		cfg.V2rayStat.Monitor.OnlineRateThreshold = defaultConfig.V2rayStat.Monitor.OnlineRateThreshold
	}

	if cfg.Timezone != "" {
		if _, err := time.LoadLocation(cfg.Timezone); err != nil {
			log.Printf("Invalid timezone value '%s', using default (empty)", cfg.Timezone)
			cfg.Timezone = defaultConfig.Timezone
		}
	}

	// Ensure Features map is initialized
	if cfg.Features == nil {
		cfg.Features = make(map[string]bool)
	}

	return cfg, nil
}

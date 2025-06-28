package monitor

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"v2ray-stat/config"
	"v2ray-stat/telegram"
)

var (
	bannedLogRegex = regexp.MustCompile(`(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(BAN|UNBAN)\s+\[Email\] = (\S+)\s+\[IP\] = (\S+)(?:\s+banned for (\d+) seconds\.)?`)
)

// MonitorBannedLog читает новые записи из файла banned.log и отправляет уведомления в Telegram.
func MonitorBanned(bannedLog *os.File, bannedOffset *int64, cfg *config.Config) error {
	bannedLog.Seek(*bannedOffset, 0)
	scanner := bufio.NewScanner(bannedLog)

	for scanner.Scan() {
		line := scanner.Text()
		matches := bannedLogRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			log.Printf("Invalid line in ban log: %s", line)
			continue
		}

		timestamp := matches[1]
		action := matches[2]
		email := matches[3]
		ip := matches[4]
		banDuration := "unknown"
		if len(matches) == 6 && matches[5] != "" {
			banDuration = matches[5] + " seconds"
		}

		var message string
		if action == "BAN" {
			message = fmt.Sprintf("🚫 IP Banned\n\n"+
				" Client:   *%s*\n"+
				" IP:   *%s*\n"+
				" Time:   *%s*\n"+
				" Duration:   *%s*", email, ip, timestamp, banDuration)
		} else {
			message = fmt.Sprintf("✅ IP Unbanned\n\n"+
				" Client:   *%s*\n"+
				" IP:   *%s*\n"+
				" Time:   *%s*", email, ip, timestamp)
		}

		if cfg.TelegramBotToken != "" && cfg.TelegramChatId != "" {
			if err := telegram.SendNotification(cfg.TelegramBotToken, cfg.TelegramChatId, message); err != nil {
				log.Printf("Error sending ban notification: %v", err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading ban log: %v", err)
		return fmt.Errorf("error reading ban log: %v", err)
	}

	pos, err := bannedLog.Seek(0, 1)
	if err != nil {
		log.Printf("Error retrieving ban log position: %v", err)
		return fmt.Errorf("error retrieving ban log position: %v", err)
	}
	*bannedOffset = pos

	return nil
}

// MonitorBannedLogRoutine запускает периодический мониторинг файла banned.log.
func MonitorBannedLog(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		bannedLog, err := os.OpenFile(cfg.BannedLogFile, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Printf("Ошибка открытия файла логов %s: %v", cfg.BannedLogFile, err)
			return
		}
		defer bannedLog.Close()

		var bannedOffset int64
		bannedLog.Seek(0, 2)
		bannedOffset, err = bannedLog.Seek(0, 1)
		if err != nil {
			log.Printf("Ошибка получения позиции файла логов банов: %v", err)
			return
		}

		ticker := time.NewTicker(10 * time.Second) // Используем тот же интервал, что и в monitorUsersAndLogs
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := MonitorBanned(bannedLog, &bannedOffset, cfg); err != nil {
					log.Printf("Error monitoring banned log: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

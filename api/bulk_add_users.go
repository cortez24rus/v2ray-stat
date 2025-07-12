package api

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"v2ray-stat/config"

	"github.com/google/uuid"
)

// generateRandomPassword generates a random 30-character password for trojan protocol using A-Za-z0-9
func generateRandomPassword() (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const length = 30
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}

// getProtocolByInboundTag determines the protocol (vless or trojan) based on inboundTag
func getProtocolByInboundTag(inboundTag string, cfg *config.Config) (string, error) {
	configPath := cfg.V2rayStat.Type
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("error reading config.json: %v", err)
	}

	switch cfg.V2rayStat.Type {
	case "xray":
		var cfgXray config.ConfigXray
		if err := json.Unmarshal(data, &cfgXray); err != nil {
			return "", fmt.Errorf("error parsing JSON: %v", err)
		}
		for _, inbound := range cfgXray.Inbounds {
			if inbound.Tag == inboundTag {
				return inbound.Protocol, nil
			}
		}
	case "singbox":
		var cfgSingBox config.ConfigSingbox
		if err := json.Unmarshal(data, &cfgSingBox); err != nil {
			return "", fmt.Errorf("error parsing JSON: %v", err)
		}
		for _, inbound := range cfgSingBox.Inbounds {
			if inbound.Tag == inboundTag {
				return inbound.Type, nil
			}
		}
	}
	return "", fmt.Errorf("inbound with tag %s not found", inboundTag)
}

// AddUsersFromFile adds users from a file with the format: user,credential[,inboundTag]
func AddUsersFromFile(file io.Reader, cfg *config.Config) error {
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			log.Printf("Строка %d: Пропущена пустая строка", lineNumber)
			continue
		}

		// Разделяем строку по первому пробелу, игнорируя комментарии
		parts := strings.SplitN(line, " ", 2)
		data := strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			// Комментарий игнорируется, не логируем
			_ = strings.TrimSpace(parts[1])
		}

		if data == "" {
			log.Printf("Строка %d: Данные до пробела пустые", lineNumber)
			continue
		}

		// Разделяем данные по запятым
		fields := strings.Split(data, ",")
		for i, field := range fields {
			fields[i] = strings.TrimSpace(field)
		}

		// Проверяем количество полей
		if len(fields) < 1 || fields[0] == "" {
			log.Printf("Строка %d: Ошибка: имя пользователя не указано в строке: %s", lineNumber, data)
			continue
		}

		user := fields[0]
		credential := ""
		if len(fields) > 1 && fields[1] != "" {
			credential = fields[1]
		}
		inboundTag := "vless-in" // Значение по умолчанию
		if len(fields) > 2 && fields[2] != "" {
			inboundTag = fields[2]
		}

		// Определяем протокол по inboundTag
		protocol, err := getProtocolByInboundTag(inboundTag, cfg)
		if err != nil {
			log.Printf("Строка %d: Ошибка определения протокола для inboundTag %s: %v", lineNumber, inboundTag, err)
			continue
		}

		// Генерация credential в зависимости от протокола
		if credential == "" {
			if protocol == "vless" {
				credential = uuid.New().String()
			} else if protocol == "trojan" {
				credential, err = generateRandomPassword()
				if err != nil {
					log.Printf("Строка %d: Ошибка генерации пароля для пользователя %s: %v", lineNumber, user, err)
					continue
				}
			} else {
				log.Printf("Строка %d: Неподдерживаемый протокол %s для inboundTag %s", lineNumber, protocol, inboundTag)
				continue
			}
		}

		if err := AddUserToConfig(user, credential, inboundTag, cfg); err != nil {
			log.Printf("Строка %d: Не удалось добавить пользователя %s: %v", lineNumber, user, err)
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения файла: %v", err)
	}
	return nil
}

// BulkAddUsersHandler обрабатывает POST-запрос с файлом пользователей
func BulkAddUsersHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Метод не поддерживается, используйте POST", http.StatusMethodNotAllowed)
			return
		}

		// Получение файла из запроса
		file, _, err := r.FormFile("users_file")
		if err != nil {
			http.Error(w, fmt.Sprintf("Ошибка получения файла: %v", err), http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Обработка файла с помощью функции из пакета bulkadd
		if err := AddUsersFromFile(file, cfg); err != nil {
			http.Error(w, fmt.Sprintf("Ошибка обработки файла: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Пользователи успешно добавлены")
	}
}

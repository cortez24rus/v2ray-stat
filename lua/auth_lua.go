package lua

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"v2ray-stat/config"
)

// AddUserToAuthLua добавляет нового пользователя в начало таблицы users в файле auth.lua
func AddUserToAuthLua(cfg *config.Config, user, uuid string) error {
	// Открываем файл для чтения
	file, err := os.Open(cfg.AuthLuaPath)
	if err != nil {
		return fmt.Errorf("failed to open auth.lua: %w", err)
	}
	defer file.Close()

	// Читаем файл построчно
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading auth.lua: %w", err)
	}

	// Ищем начало и конец таблицы users
	startIdx, endIdx := -1, -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "local users") && strings.Contains(trimmed, "=") && strings.Contains(trimmed, "{") {
			startIdx = i
			break
		}
	}
	if startIdx < 0 {
		return fmt.Errorf("users table not found in auth.lua")
	}
	for i := startIdx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "}" {
			endIdx = i
			break
		}
	}
	if endIdx < 0 {
		return fmt.Errorf("closing brace for users table not found")
	}

	// Проверяем, есть ли пользователь в таблице
	for i := startIdx + 1; i < endIdx; i++ {
		if strings.Contains(lines[i], `[`+"\""+user+"\"`+\"]") {
			return fmt.Errorf("user %s already exists in auth.lua", user)
		}
	}

	// Формируем новую запись
	newEntry := fmt.Sprintf(`  ["%s"] = "%s",`, user, uuid)

	insertPos := startIdx + 1
	lines = append(
		lines[:insertPos],
		append([]string{newEntry}, lines[insertPos:]...)..., // сдвигаем существующие записи вниз
	)

	// Перезаписываем файл
	out, err := os.Create(cfg.AuthLuaPath)
	if err != nil {
		return fmt.Errorf("failed to create auth.lua: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	for _, l := range lines {
		if _, err := writer.WriteString(l + "\n"); err != nil {
			return fmt.Errorf("error writing to auth.lua: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing writer: %w", err)
	}

	return nil
}

// DeleteUserFromAuthLua удаляет пользователя из таблицы users в файле auth.lua
func DeleteUserFromAuthLua(cfg *config.Config, user string) error {
	// Открываем файл для чтения
	file, err := os.Open(cfg.AuthLuaPath)
	if err != nil {
		return fmt.Errorf("failed to open auth.lua: %w", err)
	}
	defer file.Close()

	// Читаем файл построчно
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading auth.lua: %w", err)
	}

	// Ищем начало и конец таблицы users
	startIdx, endIdx := -1, -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "local users") && strings.Contains(trimmed, "=") && strings.Contains(trimmed, "{") {
			startIdx = i
			break
		}
	}
	if startIdx < 0 {
		return fmt.Errorf("users table not found in auth.lua")
	}
	for i := startIdx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "}" {
			endIdx = i
			break
		}
	}
	if endIdx < 0 {
		return fmt.Errorf("closing brace for users table not found")
	}

	// Ищем и удаляем строку с пользователем
	userPattern := fmt.Sprintf(`["%s"]`, user)
	removed := false
	for i := startIdx + 1; i < endIdx; i++ {
		if strings.Contains(lines[i], userPattern) {
			lines = append(lines[:i], lines[i+1:]...)
			removed = true
			endIdx-- // Сдвигаем конец таблицы
			break
		}
	}
	if !removed {
		return fmt.Errorf("user %s not found in auth.lua", user)
	}

	// Перезаписываем файл
	out, err := os.Create(cfg.AuthLuaPath)
	if err != nil {
		return fmt.Errorf("failed to create auth.lua: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("error writing to auth.lua: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing writer: %w", err)
	}

	return nil
}

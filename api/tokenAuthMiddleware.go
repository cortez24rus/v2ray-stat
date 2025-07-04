package api

import (
	"log"
	"net"
	"net/http"
	"strings"
	"v2ray-stat/config"
)

func getClientIP(r *http.Request) string {
	// Сначала пробуем X-Forwarded-For (могут быть IP через запятую)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// Берём первый IP (он от клиента)
		ips := strings.Split(fwd, ",")
		return strings.TrimSpace(ips[0])
	}

	// Затем X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Фоллбэк — то, что Go получил напрямую (будет 127.0.0.1 через прокси)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// TokenAuthMiddleware проверяет токен в заголовке Authorization.
func TokenAuthMiddleware(cfg *config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		// Если токен не задан в конфигурации, разрешаем доступ
		if cfg.APIToken == "" {
			// log.Printf("Warning: API_TOKEN not set, allowing request from %s", clientIP)
			next.ServeHTTP(w, r)
			return
		}

		// Проверяем заголовок Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("Missing Authorization header for request from %s", clientIP)
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Ожидаем формат "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("Invalid Authorization header format from %s", clientIP)
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Проверяем токен
		if parts[1] != cfg.APIToken {
			log.Printf("Invalid token from %s", clientIP)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Токен верный, продолжаем обработку
		next.ServeHTTP(w, r)
	}
}

package telegram

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
)

func SendNotification(token, chatID, message string) error {
	Hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Error retrieving hostname: %v", err)
		Hostname = "unknown"
	}

	formattedMessage := fmt.Sprintf("💻 Host: *%s*\n\n%s", Hostname, message)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?parse_mode=markdown", token)
	data := url.Values{
		"chat_id": {chatID},
		"text":    {formattedMessage},
	}

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		log.Printf("Error sending Telegram notification: %v", err)
		return fmt.Errorf("error sending notification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to send Telegram notification, status: %d", resp.StatusCode)
		return fmt.Errorf("failed to send notification, status: %d", resp.StatusCode)
	}

	// log.Printf("Telegram notification sent successfully to token %s", token)
	return nil
}

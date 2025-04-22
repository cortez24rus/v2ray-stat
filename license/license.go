// license/license.go
package license

import (
	"log"
	"time"
)

const licenseEndDate = "2025-07-22"

// VerifyLicense проверяет, не истекла ли лицензия
func VerifyLicense() {
	currentDate := time.Now()
	licenseEnd, err := time.Parse("2006-01-02", licenseEndDate)
	if err != nil {
		log.Fatalf("Ошибка парсинга даты окончания лицензии: %v", err)
	}
	if currentDate.After(licenseEnd) {
		log.Fatalf("Лицензия истекла %s. Пожалуйста, обновите лицензию.", licenseEndDate)
	}
}

package manager

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"v2ray-stat/config"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// DatabaseManager управляет последовательным доступом к базе данных через каналы запросов с приоритизацией.
type DatabaseManager struct {
	db                *sql.DB                  // Приватное поле
	cfg               *config.Config           // Конфигурация для логирования
	highPriority      chan func(*sql.DB) error // Канал для высокоприоритетных запросов
	lowPriority       chan func(*sql.DB) error // Канал для низкоприоритетных запросов
	ctx               context.Context          // Контекст
	workerPool        chan struct{}            // Пул рабочих горутин
	isClosed          bool                     // Флаг закрытия
	closedMu          sync.Mutex               // Мьютекс для isClosed
	highPriorityCount uint64                   // Счётчик высокоприоритетных запросов
	lowPriorityCount  uint64                   // Счётчик низкоприоритетных запросов
}

// NewDatabaseManager создаёт новый DatabaseManager и запускает обработку запросов.
func NewDatabaseManager(db *sql.DB, ctx context.Context, workerCount, highPriorityBuffer, lowPriorityBuffer int, cfg *config.Config) (*DatabaseManager, error) {
	if workerCount < 1 || highPriorityBuffer < 0 || lowPriorityBuffer < 0 {
		cfg.Logger.Fatal("Некорректные параметры", "workerCount", workerCount, "highPriorityBuffer", highPriorityBuffer, "lowPriorityBuffer", lowPriorityBuffer)
		return nil, fmt.Errorf("некорректные параметры: workerCount=%d, highPriorityBuffer=%d, lowPriorityBuffer=%d", workerCount, highPriorityBuffer, lowPriorityBuffer)
	}

	// Настройка пула соединений
	db.SetMaxOpenConns(1) // Только одно соединение для SQLite
	db.SetMaxIdleConns(1) // Одно простаивающее соединение

	manager := &DatabaseManager{
		db:           db,
		cfg:          cfg,
		highPriority: make(chan func(*sql.DB) error, highPriorityBuffer),
		lowPriority:  make(chan func(*sql.DB) error, lowPriorityBuffer),
		ctx:          ctx,
		workerPool:   make(chan struct{}, workerCount),
	}

	// Запуск рабочих горутин
	for i := range workerCount {
		go manager.processRequests(i)
	}
	cfg.Logger.Debug("DatabaseManager создан", "workerCount", workerCount, "highPriorityBuffer", highPriorityBuffer, "lowPriorityBuffer", lowPriorityBuffer)
	return manager, nil
}

// processRequests обрабатывает запросы из каналов с приоритетом.
func (m *DatabaseManager) processRequests(workerID int) {
	for {
		select {
		case <-m.ctx.Done():
			m.cfg.Logger.Debug("Воркер остановлен", "workerID", workerID)
			return
		case req, ok := <-m.highPriority:
			if !ok {
				m.cfg.Logger.Debug("Канал высокоприоритетных запросов закрыт", "workerID", workerID)
				return
			}
			atomic.AddUint64(&m.highPriorityCount, 1)
			m.processRequest(req, workerID, "highPriority")
		case req, ok := <-m.lowPriority:
			if !ok {
				m.cfg.Logger.Debug("Канал низкоприоритетных запросов закрыт", "workerID", workerID)
				return
			}
			atomic.AddUint64(&m.lowPriorityCount, 1)
			m.processRequest(req, workerID, "lowPriority")
		}
	}
}

func (m *DatabaseManager) processRequest(req func(*sql.DB) error, workerID int, priority string) {
	m.workerPool <- struct{}{}
	m.cfg.Logger.Trace("Обработка запроса", "workerID", workerID, "priority", priority)
	if err := req(m.db); err != nil {
		m.cfg.Logger.Error("Ошибка выполнения запроса", "workerID", workerID, "priority", priority, "error", err)
	}
	<-m.workerPool
	m.cfg.Logger.Trace("Запрос обработан", "workerID", workerID, "priority", priority)
	// Логируем текущее количество выполненных запросов для отладки
	m.cfg.Logger.Debug("Выполненные запросы воркеров",
		"высокоприоритетные", atomic.LoadUint64(&m.highPriorityCount),
		"низкоприоритетные", atomic.LoadUint64(&m.lowPriorityCount))
}

// executeOnce выполняет одну попытку отправки и выполнения запроса.
func (m *DatabaseManager) executeOnce(fn func(*sql.DB) error, priority bool, sendTimeout, waitTimeout time.Duration) error {
	errChan := make(chan error, 1)
	m.closedMu.Lock()
	if m.isClosed {
		m.closedMu.Unlock()
		m.cfg.Logger.Error("DatabaseManager закрыт")
		return fmt.Errorf("DatabaseManager закрыт")
	}
	m.closedMu.Unlock()

	// Выбор канала в зависимости от приоритета
	requestChan := m.lowPriority
	priorityStr := "lowPriority"
	if priority {
		requestChan = m.highPriority
		priorityStr = "highPriority"
	}

	// Отправка запроса в канал
	select {
	case requestChan <- func(db *sql.DB) error {
		err := fn(db)
		if err == sql.ErrNoRows {
			errChan <- nil
			return nil
		}
		errChan <- err
		return err
	}:
		m.cfg.Logger.Debug("Запрос отправлен в канал", "priority", priorityStr)
	case <-m.ctx.Done():
		m.cfg.Logger.Warn("Контекст отменён при отправке запроса", "priority", priorityStr)
		return m.ctx.Err()
	case <-time.After(sendTimeout):
		m.cfg.Logger.Error("Таймаут отправки запроса", "priority", priorityStr, "timeout", sendTimeout)
		return fmt.Errorf("таймаут отправки запроса (%s, %v)", priorityStr, sendTimeout)
	}

	// Ожидание выполнения запроса
	select {
	case err := <-errChan:
		return err
	case <-m.ctx.Done():
		m.cfg.Logger.Warn("Контекст отменён при ожидании ответа", "priority", priorityStr)
		return m.ctx.Err()
	case <-time.After(waitTimeout):
		m.cfg.Logger.Error("Таймаут ожидания ответа", "timeout", waitTimeout)
		return fmt.Errorf("таймаут ожидания ответа (%v)", waitTimeout)
	}
}

// isRetryableError проверяет, является ли ошибка временной и требует ли повторной попытки.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "database is locked") ||
		strings.Contains(err.Error(), "i/o timeout") ||
		strings.Contains(err.Error(), "connection refused")
}

// ExecuteWithTimeout отправляет функцию для выполнения на базе данных с настраиваемыми таймаутами и повторными попытками.
func (m *DatabaseManager) ExecuteWithTimeout(fn func(*sql.DB) error, priority bool, sendTimeout, waitTimeout time.Duration) error {
	const maxRetries = 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := m.executeOnce(fn, priority, sendTimeout, waitTimeout)
		if err == nil || !isRetryableError(err) {
			if err != nil {
				m.cfg.Logger.Error("Неудачная попытка выполнения запроса", "attempt", attempt, "error", err)
			}
			return err
		}
		m.cfg.Logger.Warn("Временная ошибка, повторная попытка", "attempt", attempt, "maxRetries", maxRetries, "error", err)
		time.Sleep(time.Duration(attempt*100) * time.Millisecond)
	}
	m.cfg.Logger.Error("Не удалось выполнить запрос после всех попыток", "maxRetries", maxRetries)
	return fmt.Errorf("не удалось выполнить запрос после %d попыток", maxRetries)
}

// Execute — обёртка над ExecuteWithTimeout с таймаутами по умолчанию (низкий приоритет).
func (m *DatabaseManager) Execute(fn func(*sql.DB) error) error {
	return m.ExecuteWithTimeout(fn, false, 2*time.Second, 5*time.Second)
}

// ExecuteHighPriority — обёртка для высокоприоритетных запросов.
func (m *DatabaseManager) ExecuteHighPriority(fn func(*sql.DB) error) error {
	return m.ExecuteWithTimeout(fn, true, 1*time.Second, 3*time.Second)
}

// SyncDBWithContext синхронизирует базу данных менеджера с целевой базой данных с использованием переданного контекста.
func (m *DatabaseManager) SyncDBWithContext(ctx context.Context, destDB *sql.DB, direction string) error {
	// Сразу проверяем, не завершён ли входящий контекст
	if err := ctx.Err(); err != nil {
		m.cfg.Logger.Error("Контекст отменён перед синхронизацией", "error", err)
		return err
	}

	m.cfg.Logger.Debug("Начало синхронизации базы данных", "direction", direction)

	// Получаем прямое соединение с исходной in-memory БД
	srcConn, err := m.db.Conn(ctx)
	if err != nil {
		m.cfg.Logger.Error("Не удалось получить соединение с исходной базой", "error", err)
		return fmt.Errorf("не удалось получить соединение с исходной базой: %v", err)
	}
	defer srcConn.Close()

	// Получаем соединение с файловой БД
	destConn, err := destDB.Conn(ctx)
	if err != nil {
		m.cfg.Logger.Error("Не удалось получить соединение с целевой базой", "error", err)
		return fmt.Errorf("не удалось получить соединение с целевой базой: %v", err)
	}
	defer destConn.Close()

	// Выполняем собственно бэкап
	err = srcConn.Raw(func(srcDriverConn any) error {
		return destConn.Raw(func(destDriverConn any) error {
			srcSQLiteConn, ok := srcDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				m.cfg.Logger.Error("Не удалось привести исходное соединение к *sqlite3.SQLiteConn")
				return fmt.Errorf("не удалось привести исходное соединение к *sqlite3.SQLiteConn")
			}
			destSQLiteConn, ok := destDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				m.cfg.Logger.Error("Не удалось привести целевое соединение к *sqlite3.SQLiteConn")
				return fmt.Errorf("не удалось привести целевое соединение к *sqlite3.SQLiteConn")
			}

			backup, err := destSQLiteConn.Backup("main", srcSQLiteConn, "main")
			if err != nil {
				m.cfg.Logger.Error("Не удалось инициализировать резервное копирование", "error", err)
				return fmt.Errorf("не удалось инициализировать резервное копирование: %v", err)
			}
			defer backup.Finish()

			for {
				finished, err := backup.Step(500)
				if err != nil {
					m.cfg.Logger.Error("Ошибка шага резервного копирования", "error", err)
					return fmt.Errorf("ошибка шага резервного копирования: %v", err)
				}
				m.cfg.Logger.Trace("Выполнен шаг резервного копирования", "finished", finished)
				if finished {
					break
				}
				// проверяем отмену контекста между шагами
				if ctx.Err() != nil {
					m.cfg.Logger.Warn("Контекст отменён во время резервного копирования", "error", ctx.Err())
					return ctx.Err()
				}
			}
			return nil
		})
	})
	if err != nil {
		m.cfg.Logger.Error("Ошибка синхронизации базы данных", "direction", direction, "error", err)
		return fmt.Errorf("ошибка синхронизации базы данных (%s): %v", direction, err)
	}

	m.cfg.Logger.Debug("Синхронизация базы данных завершена", "direction", direction)
	return nil
}

// Close закрывает DatabaseManager и завершает обработку запросов.
func (m *DatabaseManager) Close() {
	m.closedMu.Lock()
	defer m.closedMu.Unlock()
	if m.isClosed {
		m.cfg.Logger.Warn("DatabaseManager уже закрыт")
		return
	}
	m.isClosed = true

	m.cfg.Logger.Debug("Закрытие DatabaseManager")

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(5 * time.Second)

	for {
		select {
		case <-timeout:
			m.cfg.Logger.Warn("Таймаут закрытия DatabaseManager, принудительное закрытие каналов")
			close(m.highPriority)
			close(m.lowPriority)
			return
		case <-ticker.C:
			if len(m.highPriority) == 0 && len(m.lowPriority) == 0 {
				m.cfg.Logger.Debug("Все запросы обработаны, каналы закрыты")
				close(m.highPriority)
				close(m.lowPriority)
				return
			}
			m.cfg.Logger.Debug("Ожидание обработки запросов", "highPriorityCount", len(m.highPriority), "lowPriorityCount", len(m.lowPriority))
		}
	}
}

// DB возвращает указатель на sql.DB (используйте только для инициализации или тестирования, предпочтительно Execute/ExecuteHighPriority для операций с базой данных).
func (m *DatabaseManager) DB() *sql.DB {
	m.cfg.Logger.Warn("Прямой доступ к DB() следует избегать; используйте Execute или ExecuteHighPriority")
	return m.db
}

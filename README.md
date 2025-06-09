# v2ray-stat

API для управления пользователями и статистикой сервера v2ray-stat. Все запросы отправляются на `http://127.0.0.1:9952`. Ниже приведены доступные эндпоинты с примерами использования.
## Получение данных
### Список пользователей
- Получить список всех пользователей.

`curl -X GET http://127.0.0.1:9952/api/v1/users`

### Статистика сервера
- Получить общую статистику сервера (трафик, сессии и т.д.).

`curl -X GET http://127.0.0.1:9952/api/v1/stats`

### Статистика DNS
- Получить статистику DNS-запросов для пользователя. Параметры: email — email пользователя, count — количество записей.

`curl -X GET http://127.0.0.1:9952/api/v1/dns_stats?email=newuser&count=10`

### Очистка данных
- Очистка таблицы DNS
Удалить все записи из таблицы DNS-статистики.

`curl -X POST http://127.0.0.1:9952/api/v1/delete_dns_stats`

### Сброс трафика в таблице traffic_stats
- Сбросить значения uplink и downlink в таблице статистики трафика.

`curl -X POST http://127.0.0.1:9952/api/v1/reset_traffic_stats`

### Сброс трафика в таблице clients_stats
- Сбросить значения uplink и downlink в таблице статистики клиентов.

`curl -X POST http://127.0.0.1:9952/api/v1/reset_clients_stats`

### Сброс статистики сети
- Сбросить статистику сетевого трафика.

`curl -X POST http://127.0.0.1:9952/api/v1/reset_traffic`

### Добавление пользователя
- Добавить нового пользователя с указанным email, UUID и inbound.

`curl -X POST http://127.0.0.1:9952/api/v1/add_user -d "email=newuser&uuid=123e4567-e89b-12d3-a456-426614174000&inbound=vless-in"`

### Удаление пользователя
- Удалить пользователя по email и inbound.

`curl -X DELETE "http://127.0.0.1:9952/api/v1/delete_user?email=newuser&inbound=vless-in"`

### Включение/отключение пользователя
- Включить или отключить пользователя, указав enabled=true или enabled=false.

```
curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "email=newuser&enabled=true"
curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "email=newuser&enabled=false"
```

### Изменение лимита IP
- Установить лимит на количество IP-адресов для пользователя.

`curl -X PATCH http://127.0.0.1:9952/api/v1/update_lim_ip -d "email=newuser&lim_ip=5"`

### Изменение даты подписки
- Продлить подписку пользователя (например, на 30 дней).

`curl -X PATCH http://127.0.0.1:9952/api/v1/adjust_date -d "email=newuser&sub_end=+30:0"`

### Настройка автопродления
- Включить автопродление подписки для пользователя (например, на 30 дней).

`curl -X PATCH http://127.0.0.1:9952/api/v1/update_renew -d "email=newuser&renew=30"`

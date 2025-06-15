# v2ray-stat

API для управления пользователями и статистикой сервера v2ray-stat. Все запросы отправляются на `http://127.0.0.1:9952`. Ниже приведены доступные эндпоинты с примерами использования.
### Список пользователей
- Получить список всех пользователей.

`curl -X GET http://127.0.0.1:9952/api/v1/users`

### Статистика сервера
- Получить общую статистику сервера (трафик, сессии и т.д.).

`curl -X GET http://127.0.0.1:9952/api/v1/stats`

### Статистика DNS
- Получить статистику DNS-запросов для пользователя. Параметры: user — user пользователя, count — количество записей.

`curl -X GET http://127.0.0.1:9952/api/v1/dns_stats?user=newuser&count=10`

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
- Добавить нового пользователя с указанным user, UUID и inboundTag.

`curl -X POST http://127.0.0.1:9952/api/v1/add_user -d "user=newuser&credential=123e4567-e89b-12d3-a456-426614174000&inboundTag=vless-in"`

`curl -X POST http://127.0.0.1:9952/api/v1/add_user -d "user=newuser&credential=tAmkh1Sn4NbiJ3pGTF5V9kek1l5LWW&inboundTag=trojan-in"`

### Удаление пользователя
- Удалить пользователя по user и inboundTag.

`curl -X DELETE "http://127.0.0.1:9952/api/v1/delete_user?user=newuser&inboundTag=vless-in"`

### Включение/отключение пользователя
- Включить или отключить пользователя, указав enabled=true или enabled=false.

`curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "user=newuser&enabled=true"`

`curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "user=newuser&enabled=false"`

### Изменение лимита IP
- Установить лимит на количество IP-адресов для пользователя.

`curl -X PATCH http://127.0.0.1:9952/api/v1/update_lim_ip -d "user=newuser&lim_ip=5"`

### Изменение даты подписки
- Продлить подписку пользователя (например, на 30 дней).

`curl -X PATCH http://127.0.0.1:9952/api/v1/adjust_date -d "user=newuser&sub_end=+30:0"`

### Настройка автопродления
- Включить автопродление подписки для пользователя (например, на 30 дней).

`curl -X PATCH http://127.0.0.1:9952/api/v1/update_renew -d "user=newuser&renew=30"`

### Включение api для ядер

- Singbox
```
  "experimental": {
    "v2ray_api": {
      "listen": "127.0.0.1:9953",
      "stats": {
        "enabled": true,
        "inbounds": [
          "trojan-in",
          "vless-in"
        ],
        "outbounds": [
          "warp",
          "direct",
          "IPv4"
        ],
        "users": [
          "user1",
          "user2"
        ]
      }
    }
  }
```

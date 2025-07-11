# v2ray-stat API

API для управления пользователями и статистикой сервера **v2ray-stat**.  
Все запросы отправляются на `http://127.0.0.1:9952`.

---

## 📋 Список эндпоинтов

### Получить список всех пользователей

**GET** `/api/v1/users`

```bash
curl -X GET http://127.0.0.1:9952/api/v1/users
```

### Статистика сервера

**GET** `/api/v1/stats`
- **Параметры**:
  - `mode` (optional): Задаёт режим вывода статистики. Возможные значения:
    - `minimal` (default):
      - `traffic_stats`: `Source`, `Rate`, `Upload`, `Download`
      - `clients_stats`: `User`, `Last seen`, `Rate`, `Uplink`, `Downlink`
    - `standard`:
      - `traffic_stats`: `Source`, `Rate`, `Upload`, `Download`
      - `clients_stats`: `User`, `Last seen`, `Rate`, `Sess Up`, `Sess Down`, `Uplink`, `Downlink`
    - `extended`:
      - `traffic_stats`: `Source`, `Rate`, `Sess Up`, `Sess Down`, `Upload`, `Download`
      - `clients_stats`: `User`, `Last seen`, `Rate`, `Sess Up`, `Sess Down`, `Uplink`, `Downlink`, `Enabled`, `Sub end`, `Renew`, `Lim`, `Ips`
    - `full`:
      - `traffic_stats`: `Source`, `Rate`, `Sess Up`, `Sess Down`, `Upload`, `Download`
      - `clients_stats`: `User`, `ID`, `Last seen`, `Rate`, `Sess Up`, `Sess Down`, `Uplink`, `Downlink`, `Enabled`, `Sub end`, `Renew`, `Lim`, `Ips`, `Created`
  - `sort_by` (optional): `user`, `rate`, `enabled`, `sub_end`, `renew`, `sess_uplink`, `sess_downlink`, `uplink`, `downlink`, `lim_ip` (default: `user`)
  - `sort_order` (optional): `ASC` | `DESC` (default: `ASC`)

```bash
curl -X GET "http://127.0.0.1:9952/api/v1/stats?mode=extended&sort_by=user&sort_order=DESC"
```

### Статистика DNS

**GET** `/api/v1/dns_stats`
- **Параметры**:
  - `user`: Имя пользователя, для которого запрашивается статистика DNS.
  - `count`: Количество записей DNS-запросов для возврата.

```bash
curl -X GET "http://127.0.0.1:9952/api/v1/dns_stats?user=newuser&count=10"
```

### Удаляет все записи из таблицы DNS-статистики

**POST** `/api/v1/delete_dns_stats`

```bash
curl -X POST http://127.0.0.1:9952/api/v1/delete_dns_stats
```

### Сброс трафика в таблице traffic_stats колонок `uplink` и `downlink`

**POST** `/api/v1/reset_traffic_stats`

```bash
curl -X POST http://127.0.0.1:9952/api/v1/reset_traffic_stats
```

### Сброс трафика в таблице clients_stats колонок `uplink` и `downlink`

**POST** `/api/v1/reset_clients_stats`

```bash
curl -X POST http://127.0.0.1:9952/api/v1/reset_clients_stats
```

### Сбрасывает статистику сетевого трафика

**POST** `/api/v1/reset_traffic`

```bash
curl -X POST http://127.0.0.1:9952/api/v1/reset_traffic
```

### Добавление пользователя

**POST** `/api/v1/add_user`
- **Параметры**:
  - `user`: Имя пользователя.
  - `credential`: Идентификатор пользователя (UUID для VLESS или PASSWORD для Trojan).
  - `inboundTag`: Тег входящего соединения (например, `vless-in` или `trojan-in`).

```bash
curl -X POST http://127.0.0.1:9952/api/v1/add_user -d "user=newuser&credential=123e4567-e89b-12d3-a456-426614174000&inboundTag=vless-in"
```

### Массовое добавление пользователей

**POST** `/api/v1/bulk_add_users`
- **Параметры**:
  - `users_file`: Файл с данными пользователей в формате `user,credential,inboundTag`.
    - Формат файла:
      - `user,credential,inboundTag`: Полный формат (например, `user1,550e8400-e29b-41d4-a716-446655440000,vless-in`).
      - `user,credential`: Без `inboundTag`, используется значение по умолчанию.
      - `user`: Только имя, `credential` (UUID) генерируется автоматически.
      - `user,,inboundTag`: Имя и `inboundTag`, `credential` (UUID) генерируется автоматически.

```bash
curl -X POST "http://127.0.0.1:9952/api/v1/bulk_add_users" -F "users_file=@users.txt"
```
 - Пример файла `users.txt`:
```
user1,550e8400-e29b-41d4-a716-446655440000,vless-in  # Полный формат
user2,6ba7b810-9dad-11d1-80b4-00c04fd430c8           # Без inboundTag
user3                                                # Только имя, UUID будет сгенерирован
user4,,vless-in                                      # Имя и inboundTag, UUID будет сгенерирован
```

### Удаление пользователя

**DELETE** `/api/v1/delete_user`
- **Параметры**:
  - `user`: Имя пользователя.
  - `inboundTag`: Тег входящего соединения (например, `vless-in`).

```bash
curl -X DELETE "http://127.0.0.1:9952/api/v1/delete_user?user=newuser&inboundTag=vless-in"
```

### Включение/отключение пользователя

**PATCH** `/api/v1/set_enabled`  
- **Параметры**:
  - `user`: Имя пользователя.
  - `enabled`: Статус активности пользователя (`true` — включить, `false` — отключить).

```bash
curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "user=newuser&enabled=false"
```

### Изменение лимита IP для пользователя

**PATCH** `/api/v1/update_lim_ip`
- **Параметры**:
  - `user`: Имя пользователя.
  - `lim_ip`: Ограничение на количество IP-адресов.

```bash
curl -X PATCH http://127.0.0.1:9952/api/v1/update_lim_ip -d "user=newuser&lim_ip=5"
```

### Изменение даты подписки

**PATCH** `/api/v1/adjust_date`
- **Параметры**:
  - `user`: Имя пользователя.
  - `sub_end`: Смещение срока окончания подписки в формате `+дни:часы`, `-дни`

```bash
curl -X PATCH http://127.0.0.1:9952/api/v1/adjust_date -d "user=newuser&sub_end=+30:0"
```

### Настройка автопродления подписки

**PATCH** `/api/v1/update_renew`
- **Параметры**:
  - `user`: Имя пользователя.
  - `renew`: Период автопродления в днях.

```bash
curl -X PATCH http://127.0.0.1:9952/api/v1/update_renew -d "user=newuser&renew=30"
```

---


### Включение API для ядер

Включение API для статистики и управления в ядрах **Singbox** и **Xray**.

#### Singbox

```json
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

#### Xray

```json
"api": {
  "tag": "api",
  "listen": "127.0.0.1:9953",
  "services": [
    "HandlerService",
    "StatsService",
    "ReflectionService"
  ]
},
```
# v2ray-stat

Вывод список пользователей
    curl -X GET http://127.0.0.1:9952/api/v1/users

Вывод статистики
    curl -X GET http://127.0.0.1:9952/api/v1/stats

Вывод статистики dns
    curl -X GET http://127.0.0.1:9952/api/v1/dns_stats?email=newuser&count=10


Очистка таблицы dns
    curl -X POST http://127.0.0.1:9952/api/v1/delete_dns_stats

Очистка uplink и downlink таблицы traffic_stats
    curl -X POST http://127.0.0.1:9952/api/v1/reset_traffic_stats

Очистка uplink и downlink таблицы clients_stats
    curl -X POST http://127.0.0.1:9952/api/v1/reset_clients_stats

Сброс статистики network
    curl -X POST http://127.0.0.1:9952/api/v1/reset_traffic


Добавление пользователя
    curl -X POST http://127.0.0.1:9952/api/v1/add_user -d "email=newuser&uuid=123e4567-e89b-12d3-a456-426614174000&inbound=vless-in"

Удаление пользователя
    curl -X DELETE "http://127.0.0.1:9952/api/v1/delete_user?email=newuser&inbound=vless-in"

Включение отключение пользователя
    curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "email=newuser&enabled=true"
    curl -X PATCH http://127.0.0.1:9952/api/v1/set_enabled -d "email=newuser&enabled=false"


Смена лимита IP для пользователя
    curl -X PATCH http://127.0.0.1:9952/api/v1/update_lim_ip -d "email=newuser&lim_ip=5"

Изменение даты подписки
    curl -X PATCH http://127.0.0.1:9952/api/v1/adjust_date -d "email=newuser&sub_end=+30:0"

Автопродление
    curl -X PATCH http://127.0.0.1:9952/api/v1/update_renew -d "email=newuser&renew=30"



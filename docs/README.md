# TG CF Proxy

Данный форк представляет собой лучшее от старых версий TG-WS и новых - entrypoint SOCKS5 и redirect на сервера Cloudflare.
Подразумевается использование в качестве Docker-контейнера на backend.

# Attention! Имеется оттестированный, но всё же вайбкод!

**Локальный SOCKS5-прокси** для Telegram Desktop, который **ускоряет работу Telegram**, перенаправляя трафик через Cloudflare. Данные передаются в том же зашифрованном виде, а для работы не нужны сторонние сервера.


## Как это работает

```
Telegram Desktop → SOCKS5 Proxy (127.0.0.1:1080) → Cloudflare → Telegram DC
```

1. Приложение поднимает SOCKS5 прокси на `127.0.0.1:1080`
2. Перехватывает подключения к IP-адресам Telegram
3. Извлекает DC ID из MTProto obfuscation init-пакета
4. Устанавливает WebSocket (TLS) соединение через Cloudflare к соответствующему DC
5. Если CF недоступен или IP-адрес не является адресом Telegram, то bypass на прямое TCP-соединение

## 🚀 Быстрый старт

1. Git clone.
2. cd ./TG-WS-proxy
3. docker build -t tg-cf-proxy:1.0 .
4. Отредактируйте Docker compose файл, указав свой домен или использовать по умолчанию ( --cf-domain virkgj.com)
   Как настроить свой домен - https://github.com/DimaXA97/TG-CF-proxy/blob/main/docs/CfProxy.md
5. Создайте в папке wg0.conf, который является частью Outbound основного контейнера для выхода в интернет. 
   Если у вас другой сценарий использования - часть с TG-CF-proxy-wg можно удалить из Docker compose.
6. docker compose up -d

## Принципиальная схема интеграции в backend
CIDR Telegram media
91.105.192.0/23
91.108.56.0/22
95.161.64.0/20
149.154.160.0/20
149.154.164.0/22
149.154.172.0/22
185.76.151.0/24

CIDR Telegram calls
91.108.4.0/22
91.108.8.0/22
91.108.12.0/22
91.108.16.0/22
91.108.20.0/22
 
За конфигурацию "по умолчанию" будем принимать, что клиент перенаправляет в прокси (L7) или VPN (L3) весь свой трафик.
1. На сервере L3 (Для примера указан OpenVPN) нужно настроить роутинг, что бы все подсети TG были перенаправлены в Sing-Box.
2. На сервере L7 можно сразу разделить CIDR - Telegram calls идут в outbound зарубежного VPS, а Telegram media - [Outbound SOCKS5 -> Inbound SOCKS5 TG-CF]
3. Точка выхода в сеть TG-WS-proxy должна роутится в отдельную таблицу маршрутизации, где [0.0.0.0/0 -> VPS, CIDR Cloudflare -> Zapret] 
   CDN Cloudflare - https://www.cloudflare.com/ips-v4/#
   
<img width="1050" height="297" alt="image" src="https://raw.githubusercontent.com/DimaXA97/TG-CF-proxy/refs/heads/main/docs/backend.png" />
## Лицензия

[MIT License](LICENSE)

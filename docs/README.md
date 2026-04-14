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


## Лицензия

[MIT License](LICENSE)

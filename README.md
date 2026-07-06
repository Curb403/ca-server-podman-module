# Certificate Authority (CA) Server

## 📋 Описание

**CA Server** — это внутренний центр сертификации для выдачи и управления TLS-сертификатами в инфраструктуре микросервисов. Позволяет автоматически выпускать доверенные сертификаты для любых сервисов в локальной сети.

## 🚀 Быстрый старт

```bash
# 1. Клонирование репозитория
git clone https://github.com/Curb403/ca-server-podman-module.git
cd ca-server-podman-module

# 2. Установка зависимостей
pip install -r requirements.txt

# 3. Запуск CA сервера
python ca_server.py
``` 

## 🐳 Запуск в Podman
```bash
# Сборка образа
podman build -t ca-server .

# Запуск контейнера (фоновый режим)
podman run -d -p 8444:8444 -v ./data:/app/data --name ca-server ca-server

# Или с использованием Podman Compose
podman-compose -f podman-compose.ca.yaml up -d
``` 

## 📡 API Эндпоинты

Методы:
- GET	/api/v1/health - 	Проверка статуса CA
- POST /api/v1/certificate/request - 	Запрос нового сертификата
- GET	/api/v1/certificate/list - 	Список выданных сертификатов
- POST	/api/v1/certificate/revoke - 	Отзыв сертификата


## 📝 Пример запроса сертификата
```bash
curl -X POST http://localhost:8444/api/v1/certificate/request \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "my-service",
    "domains": ["my-service.local", "localhost"],
    "ips": ["127.0.0.1"]
  }'
```


## 🔧 Переменные окружения
- API_PORT - Порт API (:8444)
- CA_HOST - Хост(:0.0.0.0)
- CERT_VALIDITY_DAYS - Срок действия (365 дней)
- KEY_SIZE - Размер ключа 4096
## 🛠️ Управление
```bash
# Просмотр логов

tail -f logs/ca_server.log

# Список выданных сертификатов
curl http://localhost:8444/api/v1/certificate/list

# Отзыв сертификата
curl -X POST http://localhost:8444/api/v1/certificate/revoke \
  -H "Content-Type: application/json" \
  -d '{"service_name": "my-service"}'
```

## 🔒 Безопасность

- RSA ключи 4096 бит
- SHA-256 подписи
- Поддержка CRL (Certificate Revocation List)
- Серийные номера с инкрементом

## 📁 Структура
```text
certificate-authority/
├── ca_server.py          # API сервер
├── cert_manager.py       # Управление сертификатами
├── ca_config.py          # Конфигурация
├── data/                 # Данные CA
│   ├── certs/            # Выданные сертификаты
│   └── crl/              # Списки отзыва
└── requirements_ca.txt   # Зависимости
```
## 🐛 Устранение неполадок
```bash
# Проверка статуса
curl http://localhost:8444/api/v1/health

# Проверка сертификата
openssl verify -CAfile data/certs/ca.crt data/certs/service.crt
```
## 📄 Лицензия
MIT © Curb403

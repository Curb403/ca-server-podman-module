FROM python:3.11-slim

WORKDIR /app

# Установка OpenSSL и зависимостей
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Установка Python зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода CA
COPY ca_config.py .
COPY cert_manager.py .
COPY ca_server.py .

# Создание директорий
RUN mkdir -p /app/data /app/certs

# Инициализация CA
RUN python -c "from ca_config import CAConfig; CAConfig.init_ca_structure()"

# Экспорт портов
EXPOSE  8444

# Запуск сервера
CMD ["python", "ca_server.py"]

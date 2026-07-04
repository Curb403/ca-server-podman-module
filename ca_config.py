# ca_config.py
import os
from pathlib import Path
from datetime import timedelta


class CAConfig:
    # Базовые пути
    BASE_DIR = Path(__file__).parent
    DATA_DIR = BASE_DIR / 'data'
    CERTS_DIR = DATA_DIR / 'certs'
    CRL_DIR = DATA_DIR / 'crl'
    CONFIG_DIR = DATA_DIR / 'config'

    # Создание директорий
    @classmethod
    def _create_dirs(cls):
        for dir_path in [cls.DATA_DIR, cls.CERTS_DIR, cls.CRL_DIR, cls.CONFIG_DIR]:
            dir_path.mkdir(exist_ok=True, parents=True)

    # Настройки CA
    CA_NAME = "Secure Vault Internal CA"
    CA_COUNTRY = "RU"
    CA_STATE = "Moscow"
    CA_CITY = "Moscow"
    CA_ORG = "Secure Vault"
    CA_ORG_UNIT = "Security"
    CA_EMAIL = "ca@secure-vault.local"
    CA_COMMON_NAME = "Secure Vault Root CA"

    # Файлы CA
    CA_KEY_PATH = CERTS_DIR / 'ca.key'
    CA_CERT_PATH = CERTS_DIR / 'ca.crt'
    CA_SERIAL_PATH = DATA_DIR / 'serial'
    CA_DATABASE_PATH = DATA_DIR / 'index.txt'

    # Настройки сертификатов
    CERT_VALIDITY_DAYS = 365  # 1 год
    KEY_SIZE = 4096
    DIGEST_ALGO = 'sha256'

    # Настройки сервера
    CA_HOST = '0.0.0.0'
    CA_PORT = 8443
    API_PORT = 8444

    # Настройки безопасности
    ALLOWED_CLIENTS = []  # Пустой список = все разрешены
    REVOCATION_ENABLED = True

    @classmethod
    def init_ca_structure(cls):
        """Инициализация структуры CA"""
        cls._create_dirs()

        # Создаем файл серийных номеров
        if not cls.CA_SERIAL_PATH.exists():
            with open(cls.CA_SERIAL_PATH, 'w') as f:
                f.write('01')

        # Создаем файл базы данных
        if not cls.CA_DATABASE_PATH.exists():
            with open(cls.CA_DATABASE_PATH, 'w') as f:
                pass

    @classmethod
    def get_server_cert_path(cls, service_name):
        """Получить путь к сертификату сервиса"""
        return cls.CERTS_DIR / f'{service_name}.crt'

    @classmethod
    def get_server_key_path(cls, service_name):
        """Получить путь к ключу сервиса"""
        return cls.CERTS_DIR / f'{service_name}.key'


# Инициализация при импорте
CAConfig.init_ca_structure()
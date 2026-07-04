# ca_client.py
import requests
import json
import ssl
import socket
from pathlib import Path
from typing import Optional, Tuple


class CAClient:
    """Клиент для взаимодействия с CA сервером"""

    def __init__(self, ca_url: str = 'http://ca-server:8444'):
        self.ca_url = ca_url
        self.session = requests.Session()

    def request_certificate(self, service_name: str, domains: list = None, ips: list = None) -> Tuple[bool, dict]:
        """Запрос сертификата у CA"""
        try:
            payload = {
                'service_name': service_name,
                'domains': domains or [],
                'ips': ips or []
            }

            response = self.session.post(
                f'{self.ca_url}/api/v1/certificate/request',
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                # Сохраняем сертификаты локально
                self._save_certificates(service_name, data)

                return True, data
            else:
                return False, {'error': f'HTTP {response.status_code}: {response.text}'}

        except Exception as e:
            return False, {'error': str(e)}

    def _save_certificates(self, service_name: str, data: dict):
        """Сохранение сертификатов на диск"""
        cert_dir = Path('/app/certs')
        cert_dir.mkdir(exist_ok=True, parents=True)

        # Сохраняем сертификат сервиса
        cert_path = cert_dir / f'{service_name}.crt'
        with open(cert_path, 'w') as f:
            f.write(data['certificate'])

        # Сохраняем ключ сервиса
        key_path = cert_dir / f'{service_name}.key'
        with open(key_path, 'w') as f:
            f.write(data['private_key'])

        # Сохраняем CA сертификат
        ca_path = cert_dir / 'ca.crt'
        with open(ca_path, 'w') as f:
            f.write(data['ca_certificate'])

        print(f"✅ Certificates saved for {service_name}")

    def verify_certificate(self, cert_path: str) -> Tuple[bool, str]:
        """Проверка сертификата через CA"""
        try:
            with open(cert_path, 'r') as f:
                cert_content = f.read()

            response = self.session.post(
                f'{self.ca_url}/api/v1/certificate/verify',
                json={'certificate': cert_content},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return data['valid'], data['message']
            else:
                return False, f'Verification failed: {response.text}'

        except Exception as e:
            return False, str(e)

    def revoke_certificate(self, service_name: str) -> bool:
        """Отзыв сертификата"""
        try:
            response = self.session.post(
                f'{self.ca_url}/api/v1/certificate/revoke',
                json={'service_name': service_name},
                timeout=30
            )

            return response.status_code == 200 and response.json().get('success', False)

        except Exception:
            return False

    def get_ca_certificate(self) -> Optional[str]:
        """Получение CA сертификата"""
        try:
            response = self.session.get(
                f'{self.ca_url}/api/v1/ca/certificate',
                timeout=30
            )

            if response.status_code == 200:
                return response.json()['ca_certificate']

            return None

        except Exception:
            return None


# Функция для создания SSL контекста
def create_ssl_context(service_name: str) -> ssl.SSLContext:
    """Создание SSL контекста для HTTPS сервера"""
    cert_dir = Path('/app/certs')
    cert_path = cert_dir / f'{service_name}.crt'
    key_path = cert_dir / f'{service_name}.key'
    ca_path = cert_dir / 'ca.crt'

    if not all(p.exists() for p in [cert_path, key_path, ca_path]):
        raise FileNotFoundError(f"Certificates not found for {service_name}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path, key_path)
    context.load_verify_locations(ca_path)
    context.verify_mode = ssl.CERT_REQUIRED

    return context
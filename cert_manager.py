# cert_manager.py
import subprocess
import ssl
import socket
import OpenSSL
from OpenSSL import crypto
from datetime import datetime, timedelta
from pathlib import Path
import json
import hashlib
import os
from ca_config import CAConfig


class CertificateManager:
    def __init__(self):
        self.config = CAConfig
        self._ensure_ca_exists()

    def _ensure_ca_exists(self):
        """Создание CA сертификата если его нет"""
        if not (self.config.CA_KEY_PATH.exists() and self.config.CA_CERT_PATH.exists()):
            self._create_ca_certificate()

    def _create_ca_certificate(self):
        """Создание корневого CA сертификата"""
        print("🔐 Creating Root CA certificate...")

        # Создаем ключ CA
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, self.config.KEY_SIZE)

        # Создаем сертификат
        cert = crypto.X509()
        cert.set_version(2)  # X509v3
        cert.set_serial_number(1)

        # Устанавливаем срок действия
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 лет

        # Заполняем информацию
        subject = cert.get_subject()
        subject.CN = self.config.CA_COMMON_NAME
        subject.C = self.config.CA_COUNTRY
        subject.ST = self.config.CA_STATE
        subject.L = self.config.CA_CITY
        subject.O = self.config.CA_ORG
        subject.OU = self.config.CA_ORG_UNIT
        subject.emailAddress = self.config.CA_EMAIL

        # Устанавливаем публичный ключ
        cert.set_pubkey(key)

        # Устанавливаем issuer (сам подписывает себя)
        cert.set_issuer(subject)

        # Добавляем расширения (упрощенный способ без сложных extensions)
        # Basic Constraints - CA:TRUE
        cert.add_extensions([
            crypto.X509Extension(
                b'basicConstraints',
                True,
                b'CA:TRUE'
            ),
            crypto.X509Extension(
                b'keyUsage',
                True,
                b'keyCertSign, cRLSign'
            ),
            crypto.X509Extension(
                b'subjectKeyIdentifier',
                False,
                self._get_key_identifier(key)
            ),
        ])

        # Подписываем сертификат
        cert.sign(key, self.config.DIGEST_ALGO)

        # Сохраняем ключ и сертификат
        with open(self.config.CA_KEY_PATH, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open(self.config.CA_CERT_PATH, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        print(f"✅ Root CA created: {self.config.CA_CERT_PATH}")

        # Сохраняем публичный ключ для клиентов
        self._save_ca_cert_for_clients()

    def _get_key_identifier(self, key):
        """Получение идентификатора ключа в правильном формате"""
        # Получаем публичный ключ в DER формате
        pubkey_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, key)

        # Вычисляем SHA-1 хеш
        sha1_hash = hashlib.sha1(pubkey_der).digest()

        # Преобразуем в шестнадцатеричную строку (формат для X509Extension)
        hex_string = ''.join(f'{b:02x}' for b in sha1_hash)

        return hex_string.encode()

    def _save_ca_cert_for_clients(self):
        """Сохраняем CA сертификат для клиентов"""
        # Сохраняем в несколько мест для удобства
        client_paths = [
            Path('../certs/ca.crt'),  # Для основного приложения
            Path('./ca.crt'),  # В текущей директории
            self.config.CERTS_DIR / 'ca.crt'  # В директории сертификатов
        ]

        for client_path in client_paths:
            try:
                client_path.parent.mkdir(exist_ok=True, parents=True)
                import shutil
                shutil.copy(self.config.CA_CERT_PATH, client_path)
                print(f"✅ CA certificate copied: {client_path}")
            except Exception as e:
                print(f"⚠️  Could not copy to {client_path}: {e}")

    def generate_server_certificate(self, service_name, domains=None, ips=None):
        """Генерация сертификата для сервера"""
        print(f"🔑 Generating certificate for service: {service_name}")

        if domains is None:
            domains = [f'{service_name}', f'{service_name}.local']

        if ips is None:
            ips = []

        # Генерируем ключ
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, self.config.KEY_SIZE)

        # Создаем сертификат
        cert = crypto.X509()
        cert.set_version(2)

        # Получаем следующий серийный номер
        serial = self._get_next_serial()
        cert.set_serial_number(serial)

        # Устанавливаем срок действия
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.config.CERT_VALIDITY_DAYS * 24 * 60 * 60)

        # Заполняем информацию
        subject = cert.get_subject()
        subject.CN = domains[0]

        # Устанавливаем публичный ключ
        cert.set_pubkey(key)

        # Устанавливаем issuer (CA)
        ca_cert = self._load_ca_certificate()
        ca_key = self._load_ca_key()
        cert.set_issuer(ca_cert.get_subject())

        # Создаем расширения
        extensions = [
            crypto.X509Extension(
                b'basicConstraints',
                False,
                b'CA:FALSE'
            ),
            crypto.X509Extension(
                b'keyUsage',
                True,
                b'digitalSignature, keyEncipherment'
            ),
            crypto.X509Extension(
                b'extendedKeyUsage',
                True,
                b'serverAuth, clientAuth'
            ),
            crypto.X509Extension(
                b'subjectKeyIdentifier',
                False,
                self._get_key_identifier(key)
            ),
        ]

        # Добавляем Subject Alternative Names (SAN)
        san_entries = []
        for domain in domains:
            san_entries.append(f'DNS:{domain}')
        for ip in ips:
            san_entries.append(f'IP:{ip}')

        if san_entries:
            san_string = ', '.join(san_entries)
            extensions.append(
                crypto.X509Extension(
                    b'subjectAltName',
                    False,
                    san_string.encode()
                )
            )

        cert.add_extensions(extensions)

        # Подписываем сертификат
        cert.sign(ca_key, self.config.DIGEST_ALGO)

        # Сохраняем сертификат и ключ
        cert_path = self.config.get_server_cert_path(service_name)
        key_path = self.config.get_server_key_path(service_name)

        with open(cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        with open(key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        # Сохраняем информацию о сертификате
        self._save_cert_info(service_name, cert, serial, domains, ips)

        print(f"✅ Certificate generated: {cert_path}")
        return cert_path, key_path

    def _get_next_serial(self):
        """Получение следующего серийного номера"""
        serial_file = self.config.DATA_DIR / 'serial'

        if serial_file.exists():
            with open(serial_file, 'r') as f:
                content = f.read().strip()
                if content:
                    try:
                        serial = int(content, 16) + 1
                    except ValueError:
                        serial = 2
                else:
                    serial = 2
        else:
            serial = 2

        # Сохраняем новый серийный номер
        with open(serial_file, 'w') as f:
            f.write(format(serial, 'x').upper())

        return serial

    def _load_ca_certificate(self):
        """Загрузка CA сертификата"""
        with open(self.config.CA_CERT_PATH, 'rb') as f:
            return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    def _load_ca_key(self):
        """Загрузка CA ключа"""
        with open(self.config.CA_KEY_PATH, 'rb') as f:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    def _save_cert_info(self, service_name, cert, serial, domains, ips):
        """Сохранение информации о сертификате"""
        info_file = self.config.DATA_DIR / 'certificates.json'

        cert_info = {
            'service_name': service_name,
            'serial': str(serial),
            'domains': domains,
            'ips': ips,
            'issued_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=self.config.CERT_VALIDITY_DAYS)).isoformat(),
            'revoked': False
        }

        if info_file.exists():
            with open(info_file, 'r') as f:
                certs = json.load(f)
        else:
            certs = []

        # Обновляем или добавляем
        certs = [c for c in certs if c['service_name'] != service_name]
        certs.append(cert_info)

        with open(info_file, 'w') as f:
            json.dump(certs, f, indent=2)

    def revoke_certificate(self, service_name):
        """Отзыв сертификата"""
        if not self.config.REVOCATION_ENABLED:
            return False

        info_file = self.config.DATA_DIR / 'certificates.json'
        if not info_file.exists():
            return False

        with open(info_file, 'r') as f:
            certs = json.load(f)

        for cert in certs:
            if cert['service_name'] == service_name:
                cert['revoked'] = True
                cert['revoked_at'] = datetime.now().isoformat()

                # Создаем CRL
                self._generate_crl()
                break

        with open(info_file, 'w') as f:
            json.dump(certs, f, indent=2)

        return True

    def _generate_crl(self):
        """Генерация CRL (Certificate Revocation List)"""
        ca_cert = self._load_ca_certificate()
        ca_key = self._load_ca_key()

        crl = crypto.CRL()

        # Загружаем отозванные сертификаты
        info_file = self.config.DATA_DIR / 'certificates.json'
        if info_file.exists():
            with open(info_file, 'r') as f:
                certs = json.load(f)

            for cert_info in certs:
                if cert_info.get('revoked', False):
                    revoked = crypto.Revoked()
                    revoked.set_serial(cert_info['serial'])
                    revoked.set_rev_date(datetime.now().strftime('%Y%m%d%H%M%SZ'))
                    crl.add_revoked(revoked)

        crl.sign(ca_cert, ca_key, self.config.DIGEST_ALGO)

        crl_path = self.config.CRL_DIR / 'ca.crl'
        with open(crl_path, 'wb') as f:
            f.write(crl.export(crypto.FILETYPE_PEM))

        return crl_path

    def verify_certificate(self, cert_path):
        """Проверка валидности сертификата"""
        with open(cert_path, 'rb') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        ca_cert = self._load_ca_certificate()

        # Проверяем подпись
        try:
            store = crypto.X509Store()
            store.add_cert(ca_cert)
            store_ctx = crypto.X509StoreContext(store, cert)
            store_ctx.verify_certificate()

            # Проверяем дату
            now = datetime.now()
            cert_not_before = datetime.strptime(
                cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'
            )
            cert_not_after = datetime.strptime(
                cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
            )

            if now < cert_not_before:
                return False, "Certificate not yet valid"
            if now > cert_not_after:
                return False, "Certificate expired"

            # Проверяем отзыв
            if self._is_revoked(cert):
                return False, "Certificate revoked"

            return True, "Certificate valid"

        except Exception as e:
            return False, str(e)

    def _is_revoked(self, cert):
        """Проверка отзыва сертификата"""
        serial = format(cert.get_serial_number(), 'x').upper()

        info_file = self.config.DATA_DIR / 'certificates.json'
        if not info_file.exists():
            return False

        with open(info_file, 'r') as f:
            certs = json.load(f)

        for cert_info in certs:
            if cert_info['serial'] == serial:
                return cert_info.get('revoked', False)

        return False
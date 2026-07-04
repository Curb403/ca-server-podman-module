# ca_server.py
from flask import Flask, request, jsonify, send_file
import json
import os
from datetime import datetime
from pathlib import Path
from cert_manager import CertificateManager
from ca_config import CAConfig
import ssl

app = Flask(__name__)
cert_manager = CertificateManager()
config = CAConfig()


# Маршруты API
@app.route('/api/v1/health', methods=['GET'])
def health():
    """Проверка здоровья CA"""
    return jsonify({
        'status': 'healthy',
        'ca_name': config.CA_NAME,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/v1/certificate/request', methods=['POST'])
def request_certificate():
    """Запрос нового сертификата"""
    try:
        data = request.json
        service_name = data.get('service_name')
        domains = data.get('domains', [])
        ips = data.get('ips', [])

        if not service_name:
            return jsonify({'error': 'service_name is required'}), 400

        # Проверка имени сервиса
        if not service_name.replace('-', '').replace('_', '').isalnum():
            return jsonify({'error': 'Invalid service name'}), 400

        # Генерация сертификата
        cert_path, key_path = cert_manager.generate_server_certificate(
            service_name, domains, ips
        )

        # Чтение сертификата и ключа
        with open(cert_path, 'r') as f:
            cert_content = f.read()

        with open(key_path, 'r') as f:
            key_content = f.read()

        with open(config.CA_CERT_PATH, 'r') as f:
            ca_cert_content = f.read()

        return jsonify({
            'success': True,
            'service_name': service_name,
            'certificate': cert_content,
            'private_key': key_content,
            'ca_certificate': ca_cert_content,
            'domains': domains,
            'ips': ips,
            'validity_days': config.CERT_VALIDITY_DAYS
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/certificate/verify', methods=['POST'])
def verify_certificate():
    """Проверка сертификата"""
    try:
        data = request.json
        cert_content = data.get('certificate')

        if not cert_content:
            return jsonify({'error': 'certificate is required'}), 400

        # Сохраняем временно
        temp_cert = Path('/tmp/temp_cert.crt')
        with open(temp_cert, 'w') as f:
            f.write(cert_content)

        valid, message = cert_manager.verify_certificate(temp_cert)

        # Удаляем временный файл
        temp_cert.unlink()

        return jsonify({
            'valid': valid,
            'message': message
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/certificate/revoke', methods=['POST'])
def revoke_certificate():
    """Отзыв сертификата"""
    try:
        data = request.json
        service_name = data.get('service_name')

        if not service_name:
            return jsonify({'error': 'service_name is required'}), 400

        success = cert_manager.revoke_certificate(service_name)

        return jsonify({
            'success': success,
            'message': f'Certificate for {service_name} revoked' if success else 'Revocation failed'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/certificate/list', methods=['GET'])
def list_certificates():
    """Список выданных сертификатов"""
    try:
        info_file = config.DATA_DIR / 'certificates.json'

        if not info_file.exists():
            return jsonify({'certificates': []})

        with open(info_file, 'r') as f:
            certs = json.load(f)

        return jsonify({
            'certificates': certs,
            'total': len(certs)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/ca/certificate', methods=['GET'])
def get_ca_certificate():
    """Получение CA сертификата"""
    try:
        with open(config.CA_CERT_PATH, 'r') as f:
            ca_cert = f.read()

        return jsonify({
            'ca_certificate': ca_cert,
            'ca_name': config.CA_NAME
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/crl', methods=['GET'])
def get_crl():
    """Получение CRL (Certificate Revocation List)"""
    try:
        crl_path = config.CRL_DIR / 'ca.crl'

        if not crl_path.exists():
            cert_manager._generate_crl()

        if crl_path.exists():
            return send_file(crl_path, mimetype='application/pkix-crl')
        else:
            return jsonify({'error': 'CRL not available'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("🔐 Starting Certificate Authority Server...")
    config.init_ca_structure()

    # Запуск API сервера (HTTP для внутреннего использования)
    app.run(host='0.0.0.0', port=config.API_PORT, debug=False)
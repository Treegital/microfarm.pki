import logging
import pika
import threading
import typing as t
import dynaconf
from pathlib import Path
from bundle import PKI
from minicli import cli, run
from branding_iron import keys, certificate
from cryptography.hazmat.primitives import serialization
from cryptography import x509


def generate_password(length: int) -> str:
    if length < 8:
        raise ValueError(
            "Password length should be equal or superior to 8 characters.")

    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    from os import urandom
    return "".join(chars[c % len(chars)] for c in urandom(length))


def data_from_file(path: t.Union[Path, str]) -> t.Optional[bytes]:
    path = Path(path)  # idempotent.
    if not path.exists():
        raise FileNotFoundError('{path!r} does not exist.')

    if not path.is_file():
        raise TypeError('{path!r} should be a file.')

    with path.open('rb') as fd:
        data = fd.read()

    return data


def load_pki(settings):
    root_cert = certificate.pem_decrypt_x509(
        data_from_file(settings.root.cert_path)
    )
    intermediate_cert = certificate.pem_decrypt_x509(
        data_from_file(settings.intermediate.cert_path)
    )
    intermediate_key = keys.pem_decrypt_key(
        data_from_file(settings.intermediate.key_path),
        settings.intermediate.password.encode()
    )
    return PKI(intermediate_cert, intermediate_key, [root_cert])


def create_connection():
    credentials = pika.PlainCredentials("guest", "guest")
    parameters = pika.ConnectionParameters(
        "localhost", credentials=credentials
    )
    connection = pika.BlockingConnection(parameters)
    return connection


def certificate_handler(pki: PKI, stop: threading.Event):
    connection = create_connection()
    try:
        channel = connection.channel()
        generator = channel.consume("pki.certificate", inactivity_timeout=2)
        for method_frame, properties, body in generator:
            if (method_frame, properties, body) == (None, None, None):
                # Inactivity : Check for flag
                if stop.is_set():
                    break
            else:
                data = orjson.loads(body)
                print(f'generating certificate {data}')
                subject = x509.Name.from_rfc4514_string(data['identity'])
                bundle = pki.create_bundle(subject)
                password = bytes(generate_password(12), 'ascii')
                result = {
                    'profile': data['profile'],
                    'account': data['user'],
                    'serial_number': str(bundle.certificate.serial_number),
                    'fingerprint': bundle.fingerprint,
                    'pem_cert': bundle.pem_cert,
                    'pem_chain': bundle.pem_chain,
                    'pem_private_key': bundle.dump_private_key(password),
                    'valid_from': bundle.certificate.not_valid_before,
                    'valid_until': bundle.certificate.not_valid_after
                }
                channel.basic_publish(
                    exchange='service.persistence',
                    routing_key='persistence.certificate.create',
                    body=ormsgpack.packb(result),
                    properties=pika.BasicProperties(
                        content_type='application/json',
                        delivery_mode=pika.DeliveryMode.Transient)
                )
                channel.basic_ack(method_frame.delivery_tag)
    finally:
        if connection.is_open:
            connection.close()


@cli
def serve(config: Path):
    settings = dynaconf.Dynaconf(settings_files=[config])
    pki = load_pki(settings.pki)
    stopEvent = threading.Event()
    cert_service = threading.Thread(
        target=certificate_handler,
        args=[pki, stopEvent]
    )
    cert_service.start()
    try:
        stopEvent.wait()
    except KeyboardInterrupt:
        stopEvent.set()
    finally:
        cert_service.join()


if __name__ == '__main__':
    run()

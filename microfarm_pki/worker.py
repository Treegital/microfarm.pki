import asyncio
import logging
import ormsgpack
import typing as t
from pathlib import Path
from minicli import cli, run
from aio_pika import Message, connect
from aio_pika.abc import AbstractIncomingMessage
from cryptography import x509
from branding_iron import keys, certificate
from .bundle import PKI
from .pki import create_pki
from .responder import Responder


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


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
        raise FileNotFoundError(f'`{path}` does not exist.')

    if not path.is_file():
        raise TypeError(f'`{path}` should be a file.')

    with path.open('rb') as fd:
        data = fd.read()

    return data


def load_pki(settings):
    root_cert = certificate.pem_decrypt_x509(
        data_from_file(settings['root']['cert_path'])
    )
    intermediate_cert = certificate.pem_decrypt_x509(
        data_from_file(settings['intermediate']['cert_path'])
    )
    intermediate_key = keys.pem_decrypt_key(
        data_from_file(settings['intermediate']['key_path']),
        settings['intermediate']['password'].encode()
    )
    return PKI(intermediate_cert, intermediate_key, [root_cert])


class Minter:

    def __init__(self, pki: PKI):
        self.pki = pki

    def mint(self, data: dict) -> dict:
        subject = x509.Name.from_rfc4514_string(data['identity'])
        bundle = self.pki.create_bundle(subject)
        password = bytes(generate_password(12), 'ascii')
        return {
            'password': password,
            'data': {
                'account': data['user'],
                'serial_number': str(bundle.certificate.serial_number),
                'fingerprint': bundle.fingerprint,
                'pem_cert': bundle.pem_cert,
                'pem_chain': bundle.pem_chain,
                'pem_private_key': bundle.dump_private_key(password),
                'valid_from': bundle.certificate.not_valid_before,
                'valid_until': bundle.certificate.not_valid_after
            }
        }

    async def listen(self, url: str, queues: dict) -> None:
        # Perform connection
        connection = await connect(url)

        async with connection:
            # Creating a channel
            channel = await connection.channel()
            exchange = channel.default_exchange

            # Declaring queues
            request_queue = await channel.declare_queue(
                **queues['requests']
            )

            amqp_logger.info("Awaiting Certificate requests")

            async with request_queue.iterator() as qiterator:
                message: AbstractIncomingMessage
                async for message in qiterator:
                    async with message.process(requeue=True):
                        assert message.reply_to is not None
                        data = ormsgpack.unpackb(message.body)
                        result = self.mint(data)
                        response = ormsgpack.packb(result)
                        await exchange.publish(
                            Message(
                                body=response,
                                correlation_id=message.correlation_id,
                            ),
                            routing_key=message.reply_to,
                        )


@cli
async def work(config: Path):
    import tomli
    import logging.config

    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    if logconf := settings.get('logging'):
        logging.config.dictConfigClass(logconf).configure()

    pki: PKI = load_pki(settings['pki'])
    minter = Minter(pki)
    responder = Responder(pki)

    await asyncio.gather(
        minter.listen(settings['amqp']['url'], settings['amqp']['queues']),
        responder.listen(settings['amqp']['url'])
    )


@cli
def generate(config: Path):
    import tomli

    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    create_pki(settings['pki'])


if __name__ == "__main__":
    run()

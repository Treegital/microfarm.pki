import asyncio
import logging
import ormsgpack
import typing as t
from datetime import datetime, timezone
from pathlib import Path
from minicli import cli, run
from aio_pika import Message, connect, connect_robust
from aio_pika.patterns import RPC
from aio_pika.abc import AbstractIncomingMessage
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from branding_iron import keys, certificate
from .bundle import PKI
from .pki import create_pki


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


class MsgpackRPC(RPC):
    CONTENT_TYPE = "application/msgpack"

    def serialize(self, data: t.Any) -> bytes:
        return ormsgpack.packb(data)

    def deserialize(self, data: bytes) -> bytes:
        return ormsgpack.unpackb(data)


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


class PKIWorker:

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

    async def check_status(self, *,
                           pem_cert: bytes,
                           pem_chain: bytes,
                           revocation_date: str,
                           revocation_reason: str) -> bytes:
        if revocation_date:
            status = x509.ocsp.OCSPCertStatus.REVOKED
            revocation_date = datetime.fromisoformat(revocation_date)
        else:
            status = x509.ocsp.OCSPCertStatus.GOOD

        cert = x509.load_pem_x509_certificate(pem_cert)
        chain = x509.load_pem_x509_certificates(pem_chain)
        builder = x509.ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert,
            issuer=chain[0],
            algorithm=hashes.SHA256(),
            cert_status=status,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc),
            revocation_time=revocation_date,
            revocation_reason=x509.ReasonFlags[revocation_reason]
        ).responder_id(
            x509.ocsp.OCSPResponderEncoding.HASH,
            self.pki.certificate
        )
        # 'Algorithm must be None when signing via ed25519 or ed448
        # We need to make sure it's either...
        res = builder.sign(self.pki.private_key, None)
        der = res.public_bytes(serialization.Encoding.DER)
        return der

    async def rpc_responder(self, url: str):
        connection = await connect_robust(
            url,
            client_properties={"connection_name": "PKI RPC"},
        )
        channel = await connection.channel()
        rpc = await MsgpackRPC.create(channel)
        await rpc.register(
            "check_status", self.check_status, auto_delete=True)

        rpc_logger.info("Started PKI RPC channel")
        try:
            await asyncio.Future()
        finally:
            await connection.close()

    async def minter(self, url: str, queues: dict) -> None:
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
    service = PKIWorker(pki)
    await asyncio.gather(
        service.minter(
            settings['amqp']['url'], settings['amqp']['queues']),
        service.rpc_responder(settings['amqp']['url'])
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

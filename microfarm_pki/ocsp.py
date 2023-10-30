import asyncio
import logging
import typing as t
from datetime import datetime, timezone
from aio_pika import connect_robust, connect
from cryptography import x509
from cryptography.x509 import ocsp, load_pem_x509_certificate, load_pem_x509_certificates, ReasonFlags
from cryptography.hazmat.primitives import hashes, serialization
from .rpc import MsgpackRPC


rpc_logger = logging.getLogger('microfarm_pki.rpc')


class Responder:

    def __init__(self, pki, loop=None):
        self.pki = pki
        self.connection = None
        self.stopped = asyncio.Event()
        if loop is None:
            loop = asyncio.get_running_loop()
        self.loop = loop

    async def listen(self, url: str):
        await self.start(url)
        await self.stopped.wait()
        await self.close()

    def stop(self):
        self.stopped.set()

    async def close(self):
        if self.stopped.is_set():
            await self.connection.close()
            self.connection = None
            self.stopped.clear()

    async def start(self, url):
        if self.connection is not None:
            raise RuntimeError('Already started')

        self.connection = await connect_robust(
            url, loop=self.loop,
            client_properties={"connection_name": "callee"},
        )
        channel = await self.connection.channel()
        rpc = await MsgpackRPC.create(channel)
        await rpc.register(
            "check_status", self.check_status, auto_delete=True)
        self.stopped.clear()
        rpc_logger.info("PKI RPC Responder is running")

    async def check_status(self, *,
                           pem_cert: bytes,
                           pem_chain: bytes,
                           revocation_date: str,
                           revocation_reason: str) -> bytes:
        if revocation_date:
            status = ocsp.OCSPCertStatus.REVOKED
            revocation_date = datetime.fromisoformat(revocation_date)
            revocation_reason = ReasonFlags[revocation_reason]
        else:
            status = ocsp.OCSPCertStatus.GOOD
            revocation_reason = None

        cert = load_pem_x509_certificate(pem_cert)
        chain = load_pem_x509_certificates(pem_chain)
        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert,
            issuer=chain[0],
            algorithm=hashes.SHA256(),
            cert_status=status,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc),
            revocation_time=revocation_date,
            revocation_reason=revocation_reason
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH,
            self.pki.certificate
        )
        # 'Algorithm must be None when signing via ed25519 or ed448
        # We need to make sure it's either...
        res = builder.sign(self.pki.private_key, None)
        der = res.public_bytes(serialization.Encoding.DER)
        return der

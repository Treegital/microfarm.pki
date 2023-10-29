import asyncio
import logging
import typing as t
from datetime import datetime, timezone
from aio_pika import connect_robust
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from .rpc import MsgpackRPC


rpc_logger = logging.getLogger('microfarm_pki.rpc')


class Responder:

    def __init__(self, pki):
        self.pki = pki
        self.connection = None
        self.stopped = asyncio.Event()

    async def listen(self, url: str):
        await self.start(url)
        await self.stopped.wait()
        await self.stop()

    async def stop(self):
        self.stopped.set()
        await self.connection.close()
        self.connection = None

    async def start(self, url):
        if self.connection is not None:
            raise RuntimeError('Already started')

        self.connection = await connect_robust(
            url,
            client_properties={"connection_name": "PKI RPC"},
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

import asyncio
import logging
import uuid
import ormsgpack
import typing as t
from aiozmq import rpc
from pathlib import Path
from datetime import datetime
from peewee_aio import Manager
from cryptography import x509
from aio_pika.patterns import RPC
from aio_pika import Message, connect, connect_robust, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from .models import Request, Certificate
from . import request
from . import certificate
from . import pagination


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


class Ordering(t.TypedDict):
    key: str
    order: t.Literal['asc'] | t.Literal['desc']


class MsgpackRPC(RPC):
    CONTENT_TYPE = "application/msgpack"

    def serialize(self, data: t.Any) -> bytes:
        return ormsgpack.packb(data)

    def deserialize(self, data: bytes) -> bytes:
        return ormsgpack.unpackb(data)


class PKIService(rpc.AttrHandler):

    def __init__(self, manager: Manager,
                 url: str,
                 queues: dict,
                 loop: asyncio.AbstractEventLoop = None) -> None:
        self.manager = manager
        self.url = url
        if loop is None:
            loop = asyncio.get_running_loop()
        self.loop = loop
        self.queues = queues
        self.results = {}

    async def persist(self):
        connection: AbstractConnection = await connect(
            self.url, loop=self.loop
        )

        async with connection:
            channel: AbstractChannel = await connection.channel()
            await channel.set_qos(prefetch_count=1)
            certificate_queue: AbstractQueue = await channel.declare_queue(
                **self.queues['certificates']
            )
            amqp_logger.info(
                'Awaiting for generated certificate to persist.'
            )
            async with certificate_queue.iterator() as qiterator:
                message: AbstractIncomingMessage
                async for message in qiterator:
                    try:
                        certificate = ormsgpack.unpackb(message.body)
                        async with self.manager:
                            async with self.manager.connection():
                                data = certificate['data']
                                # SQLite doesn't have a Datetime Format
                                # We need to make sure it's understood
                                data['valid_from'] = datetime.strptime(
                                    data['valid_from'],
                                    '%Y-%m-%dT%H:%M:%S'
                                )
                                data['valid_until'] = datetime.strptime(
                                    data['valid_until'],
                                    '%Y-%m-%dT%H:%M:%S'
                                )
                                await Certificate.create(
                                    request_id=message.correlation_id,
                                    **data
                                )

                        if message.correlation_id in self.results:
                            self.results[message.correlation_id].set_result(
                                data['serial_number']
                            )
                    except Exception:
                        amqp_logger.exception()
                        if task := self.results.get(message.correlation_id):
                            task.set_result(False)
                        await message.reject(requeue=False)

    @rpc.method
    async def list_certificates(
            self,
            account: str,
            offset: int = 0,
            limit: int = 0,
            sort_by: t.List[Ordering] = []):

        query = certificate.account_certificates(account)
        paginated = pagination.paginate(
            pagination.sort(
                query,
                pagination.resolve_order_by(Certificate, tuple(sort_by))
            ),
            offset=offset,
            limit=limit
        )

        async with self.manager:
            async with self.manager.connection():
                results = await paginated.dicts()
                total = int(await query.count())

        return {
            "code": 200,
            "type": "PaginatedSet[CertificateInfo]",
            "description": None,
            "body": {
                "metadata": {
                    "total": total,
                    "offset": offset or None,
                    "page_size": limit or None
                },
                "items": results
            }
        }

    @rpc.method
    async def get_certificate(self, account: str, serial_number: str):
        query = certificate.account_certificate(account, serial_number)
        async with self.manager:
            async with self.manager.connection():
                try:
                    cert = await query.dicts().get()
                    return {
                        "code": 200,
                        "type": "CertificateInfo",
                        "description": "Account certificate info",
                        "body": cert
                    }
                except Certificate.DoesNotExist:
                    return {
                        "code": 404,
                        "type": "Error",
                        "description": "Certificate does not exist.",
                        "body": None
                    }

    @rpc.method
    async def get_certificate_pem(self, account: str, serial_number: str):
        query = certificate.account_certificate_pem(account, serial_number)
        async with self.manager:
            async with self.manager.connection():
                try:
                    cert = await query.namedtuples().get()
                    return {
                        "code": 200,
                        "type": "PEM",
                        "description": "Certificate chain",
                        "body": cert.pem_cert + cert.pem_chain
                    }
                except Certificate.DoesNotExist:
                    return {
                        "code": 404,
                        "type": "Error",
                        "description": "Certificate does not exist.",
                        "body": None
                    }

    @rpc.method
    async def certificate_ocsp(self, der: bytes):
        req = x509.ocsp.load_der_ocsp_request(der)
        query = certificate.certificate_pem(str(req.serial_number))
        async with self.manager:
            async with self.manager.connection():
                try:
                    cert = await query.dicts().get()
                except Certificate.DoesNotExist:
                    return {
                        "code": 404,
                        "type": "Error",
                        "description": "Certificate does not exist.",
                        "body": None
                    }

        connection = await connect_robust(self.url, loop=self.loop)
        async with connection:
            channel = await connection.channel()
            rpc = await MsgpackRPC.create(channel)
            ocsp_response = await rpc.call('check_status', kwargs=cert)
            return {
                "code": 200,
                "type": "DER",
                "description": "OCSP Response",
                "body": ocsp_response
            }

    @rpc.method
    async def list_requests(
            self,
            account: str,
            offset: int = 0,
            limit: int = 0,
            sort_by: t.List[Ordering] = []):

        query = request.account_requests(account)
        paginated = pagination.paginate(
            pagination.sort(
                query,
                pagination.resolve_order_by(Request, tuple(sort_by))
            ),
            offset=offset,
            limit=limit
        )
        async with self.manager:
            async with self.manager.connection():
                results = await paginated.dicts()
                total = int(await query.count())

        return {
            "code": 200,
            "type": "PaginatedSet[CertificateRequest]",
            "description": None,
            "body": {
                "metadata": {
                    "total": total,
                    "offset": offset or None,
                    "page_size": limit or None
                },
                "items": results
            }
        }

    @rpc.method
    async def get_request(self, account: str, request_id: str):
        query = request.account_request(account, request_id)
        async with self.manager:
            async with self.manager.connection():
                try:
                    req = await query.dicts().get()
                    return {
                        "code": 200,
                        "type": "CertificateRequest",
                        "description": "Certificate request overview.",
                        "body": req
                    }
                except Request.DoesNotExist:
                    return {
                        "code": 404,
                        "type": "Error",
                        "description": "Request does not exist.",
                        "body": None
                    }

    @rpc.method
    async def generate_certificate(self, user: str, identity: str) -> dict:
        correlation_id = uuid.uuid4().hex
        connection = await connect(self.url, loop=self.loop)
        async with connection:
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=1)
            certificate_queue = await channel.declare_queue(
                **self.queues['certificates']
            )
            request_queue = await channel.declare_queue(
                **self.queues['requests']
            )
            async with self.manager:
                async with self.manager.connection():
                    await Request.create(
                        id=correlation_id,
                        requester=user,
                        identity=identity,
                    )
                    await channel.default_exchange.publish(
                        Message(

                            ormsgpack.packb({
                                "user": user,
                                "identity": identity
                            }),
                            content_type="application/msgpack",
                            correlation_id=correlation_id,
                            reply_to=certificate_queue.name,
                            delivery_mode=DeliveryMode.PERSISTENT
                        ),
                        routing_key=request_queue.name,
                    )
        self.results[correlation_id] = self.loop.create_future()
        return {
            "code": 201,
            "type": "Token",
            "description": "Request identifier",
            "body": correlation_id
        }

    @rpc.method
    async def revoke_certificate(
            self, account: str, serial_number: str, reason: str) -> dict:

        async with self.manager:
            async with self.manager.connection():
                try:
                    await certificate.revoke_account_certificate(
                        account, serial_number, reason
                    )
                    return {
                        "code": 200,
                        "type": "Notification",
                        "description": "Certificate was revoked.",
                        "body": None
                    }
                except Certificate.DoesNotExist:
                    return {
                        "code": 404,
                        "type": "Error",
                        "description": "Certificate could not be revoked.",
                        "body": None
                    }

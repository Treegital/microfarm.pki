
import asyncio
import logging
import uuid
import ormsgpack
import typing as t
from aiozmq import rpc
from peewee_aio import Manager
from cryptography import x509
from aio_pika import Message, connect, connect_robust, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from microfarm_pki import sql
import microfarm_pki.pki.utils as crypto_utils
from microfarm_pki.rpc import MsgpackRPC


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


class Ordering(t.TypedDict):
    key: str
    order: t.Literal['asc'] | t.Literal['desc']


class PKIClerk(rpc.AttrHandler):
    """The PKI clerk is the RPC gateway to the PKI.
    It handles all the frontend requests and dispatches them.
    It communites with 3 backends:

    1. the SQL database holding the records.
    2. the minting service (AMQP)
    3. the OCSP service (AMQP RPC)
    """

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
        self.tasks: t.MutableMapping[str, asyncio.Future] = {}

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
                                await sql.create_certificate(
                                    request_id=message.correlation_id,
                                    **certificate['data']
                                )
                                await message.ack()
                                print(certificate['password'])
                        if task := self.tasks.get(message.correlation_id):
                            task.set_result(True)
                    except Exception as err:
                        amqp_logger.exception('')
                        await message.reject(requeue=False)
                        if task := self.tasks.get(message.correlation_id):
                            task.set_result(False)
                    finally:
                        if message.correlation_id in self.tasks:
                            del self.tasks[message.correlation_id]

    @rpc.method
    async def list_certificates(
            self,
            account: str,
            offset: int = 0,
            limit: int = 0,
            sort_by: t.List[Ordering] = []):

        query = sql.get_certificates(account=account)
        paginated = sql.paginate(
            sql.sort(
                query,
                sql.resolve_order_by(sql.Certificate, tuple(sort_by))
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
    async def list_valid_certificates(
            self,
            account: str,
            offset: int = 0,
            limit: int = 0,
            sort_by: t.List[Ordering] = []):

        query = sql.get_valid_certificates(account=account)
        paginated = sql.paginate(
            sql.sort(
                query,
                sql.resolve_order_by(sql.Certificate, tuple(sort_by))
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
        query = sql.get_certificate(serial_number, account=account)
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
        query = sql.get_certificate_pem(serial_number, account=account)
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
        query = sql.get_certificate_pem(str(req.serial_number))
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

        connection = await connect_robust(
            self.url, loop=self.loop,
            client_properties={"connection_name": "caller"},
        )
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

        query = sql.get_requests(account=account)
        paginated = sql.paginate(
            sql.sort(
                query,
                sql.resolve_order_by(sql.Request, tuple(sort_by))
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
        query = sql.get_request(request_id, account=account)
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
                    await sql.create_request(
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
        self.tasks[correlation_id] = asyncio.Future()
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
                    await sql.revoke_certificate(
                        serial_number, reason, account=account
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

    @rpc.method
    async def sign(
            self, account: str, data: bytes, serial_number: str, secret: str) -> dict:

        query = sql.get_valid_certificate_pem(
            serial_number, account=account
        )
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

        try:
            signature = crypto_utils.sign(
                data,
                cert['pem_cert'],
                cert['pem_chain'],
                cert['pem_private_key'],
                secret
            )
        except ValueError:
            # bad decrypt
            return {
                "code": 400,
                "type": "Error",
                "description": "Certificate could not be activated.",
                "body": None
            }
        return {
            "code": 200,
            "type": "PKC7S",
            "description": "Data was signed.",
            "body": signature
        }

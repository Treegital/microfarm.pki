import asyncio
import logging
import uuid
import ormsgpack
import typing as t
from datetime import datetime
from aiozmq import rpc
from pathlib import Path
from minicli import cli, run
from peewee_aio import Manager
from peewee import IntegrityError, JOIN
from aio_pika import Message, connect, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from .models import Request, Certificate
from microfarm_rpc import RPCResponse, PaginatedSet, CertificateInfo, CertificateRequest


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


class Ordering(t.TypedDict):
    key: str
    order: t.Literal['asc'] | t.Literal['desc']


class PKIService(rpc.AttrHandler):
    connection: AbstractConnection
    channel: AbstractChannel
    callback_queue: AbstractQueue
    loop: asyncio.AbstractEventLoop

    def __init__(self, manager: Manager,
                 url: str,
                 queues: dict,
                 loop = None) -> None:
        self.manager = manager
        self.url = url
        if loop is None:
            loop = asyncio.get_running_loop()
        self.loop = loop
        self.queues = queues
        self.results = {}

    async def persist(self):
        connection = await connect(self.url, loop=self.loop)
        async with connection:
            channel = await connection.channel()
            await channel.set_qos(prefetch_count=1)
            certificate_queue = await channel.declare_queue(
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
                    except Exception as err:
                        if message.correlation_id in self.results:
                            self.results[message.correlation_id].set_result(False)
                        await message.reject(requeue=False)

    @rpc.method
    async def list_certificates(
            self,
            account: str,
            offset: int = 0,
            limit: int = 0,
            sort_by: t.List[Ordering] = []):

        query = (
            Certificate.select(
                Certificate.account,
                Certificate.serial_number,
                Certificate.fingerprint,
                Certificate.valid_from,
                Certificate.valid_until,
                Certificate.generation_date,
                Certificate.revocation_date,
                Certificate.revocation_reason,
                Request.identity
            )
            .join(Request)
            .group_by(Certificate)
            .where(Certificate.account == account)
        )
        if sort_by:
            for sorting in sort_by:
                sort_field = getattr(Certificate, sorting['key'])
                if sorting['order'] == 'asc':
                    query = query.order_by(sort_field.asc())
                elif sorting['order'] == 'desc':
                    query = query.order_by(sort_field.desc())
                else:
                    raise NameError(direction)

        if offset:
            query = query.offset(offset)

        if limit:
            query = query.limit(limit)

        async with self.manager:
            async with self.manager.connection():
                results = await query.dicts()
                total = int(await query.count())

        data = PaginatedSet[CertificateInfo](
            metadata={
                "total": total,
                "offset": offset or None,
                "page_size": limit or None
            },
            items=results
        )
        response = RPCResponse[PaginatedSet[CertificateInfo]](
            code=200,
            type=data.__class__.__name__,
            body=data
        )
        return response.model_dump()

    @rpc.method
    async def get_certificate(self, account: str, serial_number: str):
        query = (
            Certificate.select(
                Certificate.account,
                Certificate.serial_number,
                Certificate.fingerprint,
                Certificate.valid_from,
                Certificate.valid_until,
                Certificate.generation_date,
                Certificate.revocation_date,
                Certificate.revocation_reason,
                Request.identity,
            )
            .join(Request)
            .where(Certificate.serial_number == serial_number,
                   Certificate.account == account)
            .dicts()
            .get()
        )

        async with self.manager:
            async with self.manager.connection():
                try:
                    cert = await query
                    data = CertificateInfo(**cert)
                    response = RPCResponse[CertificateInfo](
                        code=200,
                        type=data.__class__.__name__,
                        body=data
                    )
                except Certificate.DoesNotExist:
                    response = RPCResponse[str](
                        code=404,
                        type="Error",
                        description="Certificate does not exist."
                    )
        return response.model_dump()


    @rpc.method
    async def list_requests(
            self,
            account: str,
            offset: int = 0,
            limit: int = 0,
            sort_by: t.List[Ordering] = []):
        query = (
            Request.select(
                Request.id,
                Request.identity,
                Request.requester,
                Request.submission_date,
                Certificate.serial_number,
                Certificate.generation_date
            )
            .join(Certificate, JOIN.LEFT_OUTER)
            .where(Request.requester == account)
        )
        if sort_by:
            for sorting in sort_by:
                sort_field = getattr(Request, sorting['key'])
                if sorting['order'] == 'asc':
                    query = query.order_by(sort_field.asc())
                elif sorting['order'] == 'desc':
                    query = query.order_by(sort_field.desc())
                else:
                    raise NameError(direction)

        if offset:
            query = query.offset(offset)

        if limit:
            query = query.limit(limit)

        async with self.manager:
            async with self.manager.connection():
                results = await query.dicts()
                total = int(await query.count())

        data = PaginatedSet[CertificateRequest](
            metadata={
                "total": total,
                "offset": offset or None,
                "page_size": limit or None
            },
            items=results
        )
        response = RPCResponse[PaginatedSet[CertificateRequest]](
            code=200,
            type=data.__class__.__name__,
            body=data
        )
        return response.model_dump()

    @rpc.method
    async def get_request(
            self, account: str, request_id: str):
        query = (
            Request.select(
                Request.id,
                Request.identity,
                Request.requester,
                Request.submission_date,
                Certificate.serial_number,
                Certificate.fingerprint,
                Certificate.generation_date
            )
            .join(Certificate, JOIN.LEFT_OUTER)
            .where(Request.requester == account,
                   Request.requester == account)
        )
        async with self.manager:
            async with self.manager.connection():
                try:
                    req = await query.dicts().get()
                    response = RPCResponse[CertificateRequest](
                        code=200,
                        type="CertificateRequest",
                        body=req
                    )
                except Request.DoesNotExist:
                    response = RPCResponse[str](
                        code=404,
                        type="Error",
                        description="Certificate request does not exist."
                    )
        return response.model_dump()

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
        response = RPCResponse[str](
            code=201,
            type="Token",
            description="Request identifier",
            body=correlation_id
        )
        return response.model_dump()


@cli
async def serve(config: Path) -> None:
    import tomli
    import logging.config

    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    if logconf := settings.get('logging'):
        logging.config.dictConfigClass(logconf).configure()

    # debug
    logger = logging.getLogger('peewee')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    manager = Manager(settings['database']['url'])
    manager.register(Request)
    manager.register(Certificate)

    async with manager:
        async with manager.connection():
            await manager.create_tables()

    service = PKIService(
        manager,
        settings['amqp']['url'],
        settings['amqp']
    )
    server = await rpc.serve_rpc(service, bind={settings['rpc']['bind']})
    print(f" [x] PKI Service ({settings['rpc']['bind']})")
    await service.persist()
    server.close()


if __name__ == '__main__':
    run()

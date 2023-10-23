import asyncio
import logging
import uuid
import ormsgpack
import typing as t
from aiozmq import rpc
from pathlib import Path
from minicli import cli, run
from peewee_aio import Manager
from peewee import IntegrityError, fn
from aio_pika import Message, connect, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from .models import Request, Certificate


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
    async def account_certificates(
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
                Certificate.creation_date,
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

        return {
            "code": 200,
            "data": {
                "total": total,
                "offset": offset or None,
                "page_size": limit or None,
                "items": results
            }
        }

    @rpc.method
    async def get_certificate(self, account: str, serial_number: str):
        async with self.manager:
            async with self.manager.connection():
                cert = await (
                    Certificate.select(
                        Certificate.account,
                        Certificate.serial_number,
                        Certificate.fingerprint,
                        Certificate.valid_from,
                        Certificate.valid_until,
                        Certificate.creation_date,
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
        return {
            "code": 200,
            "data": {
                "item": cert
            }
        }

    @rpc.method
    async def get_certificate_request(self, account: str, request_id: str):
        async with self.manager:
            async with self.manager.connection():
                req = await (
                    Request.select(
                        Request.id,
                        Request.identity,
                        Certificate.serial_number,
                        Certificate.fingerprint,
                        Certificate.creation_date
                    )
                    .join(Request)
                    .where(Request.id == request_id,
                           Request.requester == account)
                    .dicts()
                    .get()
                )
        return {
            "data": req
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
            'code': 201,
            'message': 'Certificate request is being processed',
            'data': {
                'request': correlation_id
            }
        }


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

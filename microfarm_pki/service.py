import asyncio
import logging
import uuid
import ormsgpack
from aiozmq import rpc
from pathlib import Path
from minicli import cli, run
from peewee_aio import Manager
from peewee import JOIN
from aio_pika import Message, connect, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from .models import Request, Certificate, IntegrityError


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


class PKIService(rpc.AttrHandler):
    connection: AbstractConnection
    channel: AbstractChannel
    callback_queue: AbstractQueue
    loop: asyncio.AbstractEventLoop

    def __init__(self, manager: Manager, url: str, queues: dict, loop = None) -> None:
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
                        self.results[message.correlation_id].set_result(
                            data['serial_number']
                        )
                    except Exception as err:
                        print(err)
                        self.results[message.correlation_id].set_result(False)
                        await message.reject(requeue=False)

    @rpc.method
    async def get_certificate(self, request_id: str):
        async with self.manager:
            async with self.manager.connection():
                reqs = await self.manager.prefetch(
                    Request.select().where(Request.id == request_id),
                    Certificate
                )
                if not reqs:
                    return {"err": "Unknown certificate request"}
                else:
                    req = reqs[0]
                    if not req.certificate:
                        return {
                            "request_id": request_id,
                            "status": "pending"
                        }
                    else:
                        return {
                            "data": {}
                        }

    @rpc.method
    async def generate_certificate(self, user: str, identity: str) -> dict:
        correlation_id = str(uuid.uuid4())

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
        return {'request': correlation_id}


@cli
async def serve(config: Path) -> None:
    import tomli
    import logging.config

    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    if logconf := settings.get('logging'):
        logging.config.dictConfigClass(logconf).configure()

    manager = Manager(settings['database']['url'])
    manager.register(Request)
    manager.register(Certificate)

    async with manager:
        async with manager.connection():
            await manager.create_tables()

    service = await PKIService(manager).connect(
        settings['amqp']['url'],
        settings['amqp']
    )
    server = await rpc.serve_rpc(service, bind={settings['rpc']['bind']})
    print(f" [x] PKI Service ({settings['rpc']['bind']})")
    await service.persist()
    server.close()


if __name__ == '__main__':
    run()

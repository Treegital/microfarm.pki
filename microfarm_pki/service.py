import asyncio
import logging
import uuid
import ormsgpack
from aiozmq import rpc
from pathlib import Path
from minicli import cli, run
from peewee_aio import Manager
from aio_pika import Message, connect, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from .models import Request, Certificate


rpc_logger = logging.getLogger('microfarm_pki.rpc')
amqp_logger = logging.getLogger('microfarm_pki.amqp')


class PKIService(rpc.AttrHandler):
    connection: AbstractConnection
    channel: AbstractChannel
    callback_queue: AbstractQueue
    loop: asyncio.AbstractEventLoop

    def __init__(self, manager: Manager) -> None:
        self.manager = manager
        self.loop = asyncio.get_running_loop()

    async def connect(self, config: dict) -> "PKIService":
        self.connection = await connect(config['url'], loop=self.loop)
        self.channel = await self.connection.channel()
        self.request_queue = await self.channel.declare_queue(
            **config['requests']
        )
        self.certificate_queue = await self.channel.declare_queue(
            **config['certificates']
        )
        return self

    async def persist(self):
        amqp_logger.info('Awaiting for generated certificate to persist.')
        async with self.certificate_queue.iterator() as qiterator:
            message: AbstractIncomingMessage
            async for message in qiterator:
                try:
                    certificate = ormsgpack.unpackb(message.body)
                    async with self.manager:
                        async with self.manager.connection():
                            await Certificate.create(
                                request_id=message.correlation_id,
                                **certificate['data']
                            )
                except Exception as err:
                    print(err)
                    await message.reject(requeue=False)

    @rpc.method
    async def generate_certificate(self, user: str, identity: str) -> dict:
        correlation_id = str(uuid.uuid4())
        async with self.manager:
            async with self.manager.connection():
                await Request.create(
                    id=correlation_id,
                    requester=user,
                    identity=identity,
                )

                await self.channel.default_exchange.publish(
                    Message(
                        ormsgpack.packb({
                            "user": user,
                            "identity": identity
                        }),
                        content_type="application/msgpack",
                        correlation_id=correlation_id,
                        reply_to=self.certificate_queue.name,
                        delivery_mode=DeliveryMode.PERSISTENT
                    ),
                    routing_key=self.request_queue.name,
                )

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

    service = await PKIService(manager).connect(settings['amqp'])
    server = await rpc.serve_rpc(service, bind={settings['rpc']['bind']})
    print(f" [x] PKI Service ({settings['rpc']['bind']})")
    await service.persist()
    server.close()


if __name__ == '__main__':
    run()

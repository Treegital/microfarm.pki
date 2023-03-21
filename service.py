import asyncio
import logging
import threading
import typing as t
import dynaconf
import uuid
import ormsgpack
from aiozmq import rpc
from pathlib import Path
from minicli import cli, run
from aio_pika import Message, connect, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from models import manager, Request, Certificate


class PKIService(rpc.AttrHandler):
    connection: AbstractConnection
    channel: AbstractChannel
    callback_queue: AbstractQueue
    loop: asyncio.AbstractEventLoop

    def __init__(self, manager) -> None:
        self.manager = manager
        self.loop = asyncio.get_running_loop()

    async def connect(self) -> "PKI":
        self.connection = await connect(
            "amqp://guest:guest@localhost/", loop=self.loop,
        )
        self.channel = await self.connection.channel()
        self.request_queue = await self.channel.declare_queue(
            'pki.requests',
            durable=True,
            exclusive=False,
            auto_delete=False
        )
        self.certificate_queue = await self.channel.declare_queue(
            'pki.certificates',
            durable=True,
            exclusive=False,
            auto_delete=False
        )
        return self

    async def persist(self):
        async with self.certificate_queue.iterator() as qiterator:
            message: AbstractIncomingMessage
            async for message in qiterator:
                try:
                    certificate = ormsgpack.unpackb(message.body)
                    async with self.manager:
                        async with self.manager.connection():
                            request = await Certificate.create(
                                request_id=message.correlation_id,
                                **certificate['data']
                            )
                except Exception as err:
                    print(err)
                    await message.reject(requeue=False)

    @rpc.method
    async def generate_certificate(self, data: dict) -> dict:
        correlation_id = str(uuid.uuid4())
        async with self.manager:
            async with self.manager.connection():
                request = await Request.create(
                    id=correlation_id,
                    requester=data['user'],
                    identity=data['identity'],
                )

                await self.channel.default_exchange.publish(
                    Message(
                        ormsgpack.packb(data),
                        content_type="application/msgpack",
                        correlation_id=correlation_id,
                        reply_to=self.certificate_queue.name,
                        delivery_mode=DeliveryMode.PERSISTENT
                    ),
                    routing_key=self.request_queue.name,
                )

        return {'request': correlation_id}


@cli
async def serve(host: str = "127.0.0.1", port: int = 7000):
    async with manager:
        async with manager.connection():
            await Request.create_table()
            await Certificate.create_table()

    service = await PKIService(manager).connect()
    server = await rpc.serve_rpc(service, bind=f'tcp://{host}:{port}')
    response = await service.generate_certificate({
        'user': 'test',
        'identity': ("ST=Florida,O=IBM,OU=Marketing,L=Tampa,"
                     "1.2.840.113549.1.9.1=johndoe@example.com,"
                     "C=US,CN=John Doe")
    })
    await service.persist()


if __name__ == '__main__':
    run()

import asyncio
import logging
import uuid
import ormsgpack
import typing as t
from aiozmq import rpc
from pathlib import Path
from minicli import cli, run
from sqlalchemy import select
from sqlalchemy.sql.functions import func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from aio_pika import Message, connect, DeliveryMode
from aio_pika.abc import (
    AbstractChannel, AbstractConnection, AbstractQueue,
    AbstractIncomingMessage
)
from .models import reg, Request, Certificate


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

    def __init__(self, session, url: str, queues: dict, loop = None) -> None:
        self.session = session
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
                        async with self.session() as session:
                            async with session.begin():
                                data = certificate['data']
                                item = Certificate(
                                    request_id=message.correlation_id,
                                    **data
                                )
                                session.add(item)

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

        query = select(
            Certificate.account,
            Certificate.serial_number,
            Certificate.fingerprint,
            Certificate.valid_from,
            Certificate.valid_until,
            Certificate.creation_date,
            Certificate.revocation_date,
            Certificate.revocation_reason
        )\
        .where(Certificate.account == account)

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

        async with self.session() as session:
            result = await session.execute(query)
            certs = [dict(row) for row in result.mappings().all()]
            result = await session.execute(func.count(Certificate.serial_number))
            total = result.scalar()

        return {
            "code": 200,
            "data": {
                "total": total,
                "offset": offset or None,
                "page_size": limit or None,
                "items": certs
            }
        }

    @rpc.method
    async def get_certificate(self, account: str, serial_number: str):
        async with self.session() as session:
            result = await session.execute(
                select(
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
                .join_from(Certificate, Request)
                .where(Certificate.serial_number == serial_number)
            )
            cert = result.mappings().one()
        return {
            "code": 200,
            "data": {
                "item": dict(cert)
            }
        }

    @rpc.method
    async def get_certificate_request(self, account: str, request_id: str):
        async with self.session() as session:
            result = await session.execute(
                select(Request)
                .where(Request.id == request_id, Request.requester == account)
                .options(selectinload(Request.certificate))
            )
            req = result.scalars().one()
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
            async with self.session() as session:
                async with session.begin():
                    item = Request(
                        id=correlation_id,
                        requester=user,
                        identity=identity,
                    )
                    session.add(item)
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

    engine = create_async_engine(settings['database']['url'])
    async_session = async_sessionmaker(engine, expire_on_commit=True)

    async with engine.begin() as conn:
        await conn.run_sync(reg.metadata.create_all)

    service = PKIService(async_session, settings['amqp']['url'], settings['amqp'])
    server = await rpc.serve_rpc(service, bind={settings['rpc']['bind']})
    print(f" [x] PKI Service ({settings['rpc']['bind']})")
    await service.persist()
    server.close()


if __name__ == '__main__':
    run()

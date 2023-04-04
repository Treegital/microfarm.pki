import uuid
import asyncio
from minicli import cli, run
from sqlalchemy import select
from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, selectinload
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import registry
from cryptography.x509 import ReasonFlags


reg = registry()

def creation_date():
    # Separate method to facilitate testing
    return datetime.utcnow()


@reg.mapped_as_dataclass
class Request:

    __tablename__ = "requests"

    requester: Mapped[str]
    identity: Mapped[str]

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, insert_default=uuid.uuid4, default=None)

    creation_date: Mapped[datetime] = mapped_column(
        insert_default=creation_date, default=None)

    certificate: Mapped["Certificate"] = relationship(
        back_populates="request", default=None
    )


@reg.mapped_as_dataclass
class Certificate:
    __tablename__ = "certificates"

    serial_number: Mapped[str] = mapped_column(primary_key=True)
    fingerprint: Mapped[str]
    pem_cert: Mapped[bytes]
    pem_chain: Mapped[bytes]
    pem_private_key: Mapped[bytes]
    valid_from: Mapped[datetime]
    valid_until: Mapped[datetime]
    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("requests.id")
    )

    creation_date: Mapped[datetime] = mapped_column(
        insert_default=creation_date, default=None)
    revocation_date: Mapped[datetime] = mapped_column(default=None)
    revocation_reason: Mapped[ReasonFlags] = mapped_column(default=None)
    request: Mapped[Request] = relationship(init=False)


@cli
async def insert():
    engine = create_async_engine('sqlite+aiosqlite:///certificates.db')
    async_session = async_sessionmaker(engine, expire_on_commit=True)

    async with engine.begin() as conn:
        await conn.run_sync(reg.metadata.create_all)

    async with async_session() as session:
        async with session.begin():
            req = Request(requester='test', identity='toto')
            session.add(req)
            await session.flush()
            rid = req.id

    async with async_session() as session:
        async with session.begin():
            item = Certificate(
                serial_number=str(rid),
                fingerprint=str(rid),
                pem_cert=b"cert",
                pem_chain=b"chain",
                pem_private_key=b"key",
                valid_from=creation_date(),
                valid_until=creation_date(),
                request_id=rid,
            )
            session.add(item)
            await session.flush()


    async with async_session() as session:
        result = await session.execute(select(Request).options(selectinload(Request.certificate)))
        for res in result.scalars():
            import pdb
            pdb.set_trace()
            print(res)



if __name__ == '__main__':
    run()

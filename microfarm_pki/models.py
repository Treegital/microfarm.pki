import uuid
import asyncio
from sqlalchemy import select
from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, registry, relationship, selectinload
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

    id: Mapped[str] = mapped_column(primary_key=True)

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
    account: Mapped[str]
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

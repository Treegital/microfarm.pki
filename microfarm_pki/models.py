import pydantic
from typing import Optional
from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column, registry, relationship
from cryptography.x509 import ReasonFlags


reg = registry()


def creation_date():
    # Separate method to facilitate testing
    return datetime.utcnow()


@reg.mapped_as_dataclass(dataclass_callable=pydantic.dataclasses.dataclass)
class Certificate:
    __tablename__ = "certificates"

    account: Mapped[str]
    serial_number: Mapped[str] = mapped_column(primary_key=True)
    fingerprint: Mapped[str]
    pem_cert: Mapped[bytes]
    pem_chain: Mapped[bytes]
    pem_private_key: Mapped[bytes]
    valid_from: Mapped[datetime]
    valid_until: Mapped[datetime]
    request_id: Mapped[str] = mapped_column(
        ForeignKey("requests.id")
    )

    creation_date: Mapped[datetime] = mapped_column(
        insert_default=creation_date, default=None)
    revocation_date: Mapped[Optional[datetime]] = mapped_column(
        default=None)
    revocation_reason: Mapped[Optional[ReasonFlags]] = mapped_column(
        default=None)

    request: Mapped["Request"] = relationship(
        default=None, back_populates="certificate", uselist=False)


@reg.mapped_as_dataclass(dataclass_callable=pydantic.dataclasses.dataclass)
class Request:

    __tablename__ = "requests"

    requester: Mapped[str]
    identity: Mapped[str]

    id: Mapped[str] = mapped_column(primary_key=True)

    creation_date: Mapped[datetime] = mapped_column(
        insert_default=creation_date, default=None)

    certificate: Mapped[Certificate] = relationship(
        default=None, uselist=False, back_populates="request")

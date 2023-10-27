import peewee
import typing as t
from enum import Enum
from peewee_aio import AIOModel
from datetime import datetime
from cryptography.x509 import ReasonFlags


def creation_date():
    # Separate method to facilitate testing
    return datetime.utcnow()


class EnumField(peewee.CharField):
    """
    This class enable an Enum like field for Peewee
    """

    def __init__(
            self, enum: type[Enum], *args: t.Any, **kwargs: t.Any) -> None:
        super().__init__(*args, **kwargs)
        self.enum = enum

    def db_value(self, value: t.Any) -> t.Any:
        if value is None:
            return None
        return value.value

    def python_value(self, value: t.Any) -> t.Any:
        if value is None and self.null:
            return value
        return self.enum(value)


class Request(AIOModel):

    class Meta:
        table_name = 'requests'

    id = peewee.FixedCharField(max_length=32, primary_key=True)
    requester = peewee.CharField()
    identity = peewee.CharField()
    submission_date = peewee.DateTimeField(default=creation_date)


class Certificate(AIOModel):

    class Meta:
        table_name = 'certificates'

    account = peewee.CharField()
    serial_number = peewee.CharField(primary_key=True)
    fingerprint = peewee.CharField(unique=True)
    pem_cert = peewee.BlobField()
    pem_chain = peewee.BlobField()
    pem_private_key = peewee.BlobField()
    valid_from = peewee.DateTimeField()
    valid_until = peewee.DateTimeField()
    generation_date = peewee.DateTimeField(default=creation_date)
    revocation_date = peewee.DateTimeField(null=True)
    revocation_reason = EnumField(ReasonFlags, null=True)
    request_id = peewee.ForeignKeyField(
        Request, backref='certificate', unique=True)

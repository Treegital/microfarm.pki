import peewee
from peewee_aio import AIOModel
from datetime import datetime
from cryptography.x509 import ReasonFlags
from peewee import IntegrityError


def creation_date():
    # Separate method to facilitate testing
    return datetime.utcnow()


class EnumField(peewee.CharField):

    def __init__(self, choices, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.choices = choices

    def db_value(self, value):
        if value is None:
            return None
        return value.value

    def python_value(self, value):
        if value is None and self.null:
            return value
        return self.choices(value)


class Request(AIOModel):

    class Meta:
        table_name = 'requests'

    id = peewee.UUIDField(primary_key=True)
    requester = peewee.CharField()
    identity = peewee.CharField()
    creation_date = peewee.DateTimeField(default=creation_date)


class Certificate(AIOModel):

    class Meta:
        table_name = 'certificates'

    serial_number = peewee.CharField(primary_key=True)
    fingerprint = peewee.CharField(unique=True)
    pem_cert = peewee.BlobField()
    pem_chain = peewee.BlobField()
    pem_private_key = peewee.BlobField()
    valid_from = peewee.DateTimeField()
    valid_until = peewee.DateTimeField()
    creation_date = peewee.DateTimeField(default=creation_date)
    revocation_date = peewee.DateTimeField(null=True)
    revocation_reason = EnumField(ReasonFlags, null=True)
    request_id = peewee.ForeignKeyField(
        Request, backref='certificate', unique=True)

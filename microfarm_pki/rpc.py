import typing as t
import ormsgpack
from aio_pika.patterns import RPC


class MsgpackRPC(RPC):
    CONTENT_TYPE = "application/msgpack"

    def serialize(self, data: t.Any) -> bytes:
        return ormsgpack.packb(data)

    def deserialize(self, data: bytes) -> bytes:
        return ormsgpack.unpackb(data)

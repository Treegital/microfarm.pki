import asyncio
import pytest
import pytest_asyncio
import testing.rabbitmq
from uuid import UUID
from aiozmq import rpc
from peewee_aio import Manager
from branding_iron import keys, certificate
from microfarm_pki.bundle import PKI
from microfarm_pki.models import Request, Certificate
from microfarm_pki.service import PKIService
from microfarm_pki.worker import Minter
from microfarm_pki.responder import Responder


root_cert = certificate.pem_decrypt_x509(
    b"""-----BEGIN CERTIFICATE-----
MIICBDCCAYSgAwIBAgIRAOwChr9xI0vCnG2fmqtspyEwBQYDK2VxMHIxFDASBgNV
BAMMC015IFJlZ2lzdGVyMQswCQYDVQQGEwJGUjEmMCQGCSqGSIb3DQEJARYXbXkt
cmVnaXN0ZXJAZXhhbXBsZS5jb20xDzANBgNVBAcMBkRyYW5jeTEUMBIGA1UECgwL
TXkgUmVnaXN0ZXIwHhcNMjMwMzIyMDAwMDAwWhcNMjQwMzIyMjM1OTU5WjByMRQw
EgYDVQQDDAtNeSBSZWdpc3RlcjELMAkGA1UEBhMCRlIxJjAkBgkqhkiG9w0BCQEW
F215LXJlZ2lzdGVyQGV4YW1wbGUuY29tMQ8wDQYDVQQHDAZEcmFuY3kxFDASBgNV
BAoMC015IFJlZ2lzdGVyMEMwBQYDK2VxAzoA8T2cfgMIIebCJXiykBv6Kq96916K
geS7kV0FfpPSUfEu/86gwkwkWaF87aoWC6h0PVRioON0P2+AoxYwFDASBgNVHRMB
Af8ECDAGAQH/AgECMAUGAytlcQNzAEHeaFUWwKMYyPqt5s6n8ILQ95ePt84YUbes
rpKWrq8zidWDBIsja5bF6GWkv5ufgxPF53Bi83xbAIsRmAX4sgX/KxlsDtnXpwPW
Z3+UG35NgYDCp7fJyOB8K2Sy42piKhrDibpMi2l7RTfyQgEDSZoMAA==
-----END CERTIFICATE-----""")


intermediate_key = keys.pem_decrypt_key(b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIE3PEifCx+MTK4dTLl/pnl1Hyk+TubvXtqZ94zD8oQS6
-----END PRIVATE KEY-----""")

intermediate_cert = certificate.pem_decrypt_x509(
    b"""-----BEGIN CERTIFICATE-----
MIIB3zCCAV+gAwIBAgIRAIglTA+yY0Dorm0mlK9LtCEwBQYDK2VxMHIxFDASBgNV
BAMMC015IFJlZ2lzdGVyMQswCQYDVQQGEwJGUjEmMCQGCSqGSIb3DQEJARYXbXkt
cmVnaXN0ZXJAZXhhbXBsZS5jb20xDzANBgNVBAcMBkRyYW5jeTEUMBIGA1UECgwL
TXkgUmVnaXN0ZXIwHhcNMjMwMzIxMDAwMDAwWhcNMjUwMzIxMjM1OTU5WjBpMRIw
EAYDVQQDDAlDZXJ0aUZhcm0xCzAJBgNVBAYTAkZJMR4wHAYJKoZIhvcNAQkBFg9h
cHBAZXhhbXBsZS5jb20xEjAQBgNVBAcMCUNlcnRpTGFuZDESMBAGA1UECgwJQ2Vy
dGlGYXJtMCowBQYDK2VwAyEALpZaqFmXfnu9c4VPoJnkGEVATbdi0D0WflcuHmH9
N8ujEzARMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VxA3MAKU4wNHnuUr6e1Lc536Ba
CXISek5VX3JXBJcMvaLUWWVM93g/4fhhUNbvy6Ov8UhJfie0jcB6Zl6AFz9gDwSj
D4s14I/0qV0HncegmwakWtT/my6hD93Vzrl98k2CyFIAdrgRmXrkd+Q3AvzQr04g
cz0A
-----END CERTIFICATE-----""")


QUEUES = {
  "requests": {
      "name": "pki.requests",
      "durable": True,
      "exclusive": False,
      "auto_delete": False,
  },
  "certificates": {
      "name": "pki.certificates",
      "durable": True,
      "exclusive": False,
      "auto_delete": False,
  }
}


@pytest.fixture(scope="function")
def rabbitmq():
    with testing.rabbitmq.RabbitMQServer() as rmq:
        yield rmq


@pytest.fixture(scope="module")
def pki():
    return PKI(intermediate_cert, intermediate_key, [root_cert])


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_manager(tmpdir_factory):
    path = tmpdir_factory.mktemp("databases").join("test.db")
    manager = Manager(f'aiosqlite:///{path}')
    manager.register(Request)
    manager.register(Certificate)

    async with manager:
        async with manager.connection():
            await Request.create_table()
            await Certificate.create_table()

    return manager


@pytest_asyncio.fixture(scope="function")
async def service(db_manager, event_loop, rabbitmq):
    service = PKIService(
        db_manager,
        url=rabbitmq.url(),
        queues=QUEUES,
        loop=event_loop
    )
    return service


@pytest.fixture(scope="function")
def minter(pki, event_loop, rabbitmq):
    service = Minter(pki)
    return service.listen(rabbitmq.url(), QUEUES)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def pki_responder(pki, event_loop, rabbitmq):
    service = Responder(pki)
    await service.start(rabbitmq.url())
    yield service
    await service.stop()


@pytest_asyncio.fixture(scope="function")
async def pki_rpcservice(service):
    server = await rpc.serve_rpc(service, bind="inproc://test")
    try:
        yield server
    finally:
        server.close()
        await server.wait_closed()


@pytest_asyncio.fixture(scope="function")
async def pki_rpcclient():
    client = await rpc.connect_rpc(connect="inproc://test", timeout=0.5)
    try:
        yield client.call
    finally:
        client.close()

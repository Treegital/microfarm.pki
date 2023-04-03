import asyncio
import pytest
import time
from freezegun import freeze_time
from branding_iron.identity import Identity


@pytest.mark.asyncio
async def test_request_certificate(
        service, pki_rpcservice, pki_rpcclient, minter, event_loop):

    identity = Identity(
        common_name="Tester",
        business_category="pytest"
    )

    response = await pki_rpcclient.generate_certificate(
        'test', str(identity))

    assert list(response.keys()) == ['request']

    request_id = response['request']
    response = await pki_rpcclient.get_certificate(request_id)
    assert response == {
        "request_id": request_id,
        "status": "pending"
    }

    task = service.results[request_id]
    assert task.done() is False

    worker = asyncio.ensure_future(minter, loop=event_loop)
    persist = asyncio.ensure_future(service.persist(), loop=event_loop)
    done, pending = await asyncio.wait(
        [task, worker, persist], return_when=asyncio.FIRST_COMPLETED)
    assert task.done() is True
    for tc in pending:
        tc.cancel()

    response = await pki_rpcclient.get_certificate(request_id)
    assert response == {
        'data': {}
    }


@pytest.mark.asyncio
async def test_request_certificate_wrong_id(pki_rpcservice, pki_rpcclient):
    """bogus or malformed identity. FIXME
    """

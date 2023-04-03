import pytest
import time
from freezegun import freeze_time
from branding_iron.identity import Identity


@pytest.mark.asyncio
async def test_request_certificate(pki_rpcservice, pki_rpcclient):

    identity = Identity(
        common_name="Tester",
        business_category="pytest")

    response = await pki_rpcclient.generate_certificate(
        'test', str(identity))

    assert list(response.keys()) == ['request']


@pytest.mark.asyncio
async def test_request_certificate_wrong_id(pki_rpcservice, pki_rpcclient):
    """bogus or malformed identity. FIXME
    """

import asyncio
import pytest
import time
import hamcrest
from datetime import datetime
from freezegun import freeze_time
from branding_iron.identity import Identity


@pytest.mark.asyncio
async def test_request_certificate(
        service, pki_rpcservice, pki_rpcclient, minter, event_loop):


    response = await pki_rpcclient.list_requests("test")
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "PaginatedSet[CertificateRequest]",
        "body": {
            "metadata": {
                "total": 0,
                "offset": None,
                "page_size": None
            },
            "items": ()
        }
    }))

    response = await pki_rpcclient.list_certificates("test")
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "PaginatedSet[CertificateInfo]",
        "body": {
            "metadata": {
                "total": 0,
                "offset": None,
                "page_size": None
            },
            "items": ()
        }
    }))

    identity = Identity(
        common_name="Tester",
        business_category="pytest"
    )

    response = await pki_rpcclient.generate_certificate(
        "test", str(identity))

    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 201,
        "type": "Token",
        "description": "Request identifier",
        "body": hamcrest.instance_of(str)
    }))

    request_id = response["body"]
    response = await pki_rpcclient.get_request("test", request_id)
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "CertificateRequest",
        "body": hamcrest.has_entries({
            "id": request_id,
            "requester": "test",
            "identity": "2.5.4.15=pytest,CN=Tester",
            "submission_date": hamcrest.instance_of(datetime),
            "generation_date": None,
            "serial_number": None
        })
    }))

    task = service.results[request_id]
    assert task.done() is False

    worker = asyncio.ensure_future(minter, loop=event_loop)
    persist = asyncio.ensure_future(service.persist(), loop=event_loop)
    done, pending = await asyncio.wait(
        [task, worker, persist], return_when=asyncio.FIRST_COMPLETED)
    assert task.done() is True
    for tc in pending:
        tc.cancel()

    response = await pki_rpcclient.get_request("test", request_id)
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "CertificateRequest",
        "body": hamcrest.has_entries({
            "id": request_id,
            "requester": "test",
            "identity": "2.5.4.15=pytest,CN=Tester",
            "submission_date": hamcrest.instance_of(datetime),
            "generation_date": hamcrest.instance_of(datetime),
            "serial_number": hamcrest.instance_of(str)
        })
    }))
    serial_number = response['body']['serial_number']

    response = await pki_rpcclient.list_requests("test")
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "PaginatedSet[CertificateRequest]",
        "description": None,
        "body": hamcrest.has_entries({
            "metadata": {
                "total": 1,
                "offset": None,
                "page_size": None
            },
            "items": hamcrest.contains_exactly(
                hamcrest.has_entries({
                    "id": request_id,
                    "requester": "test",
                    "identity": "2.5.4.15=pytest,CN=Tester",
                    "submission_date": hamcrest.instance_of(datetime),
                    "generation_date": hamcrest.instance_of(datetime),
                    "serial_number": hamcrest.instance_of(str)
                })
            )
        })
    }))

    response = await pki_rpcclient.list_certificates("test")
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "PaginatedSet[CertificateInfo]",
        "description": None,
        "body": hamcrest.has_entries({
            "metadata": {
                "total": 1,
                "offset": None,
                "page_size": None
            },
            "items": hamcrest.contains_exactly(
                hamcrest.has_entries({
                    "account": "test",
                    "status": "active",
                    "serial_number": hamcrest.instance_of(str),
                    "fingerprint": hamcrest.instance_of(str),
                    "valid_from": hamcrest.instance_of(datetime),
                    "valid_until": hamcrest.instance_of(datetime),
                    "generation_date": hamcrest.instance_of(datetime),
                    "revocation_date": None,
                    "revocation_reason": None,
                    "identity": "2.5.4.15=pytest,CN=Tester"
                })
            )
        })
    }))

    response = await pki_rpcclient.get_certificate("test", serial_number)
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "CertificateInfo",
        "description": "Account certificate info",
        "body": hamcrest.has_entries({
            "account": "test",
            "status": "active",
            "serial_number": serial_number,
            "fingerprint": hamcrest.instance_of(str),
            "valid_from": hamcrest.instance_of(datetime),
            "valid_until": hamcrest.instance_of(datetime),
            "generation_date": hamcrest.instance_of(datetime),
            "revocation_date": None,
            "revocation_reason": None,
            "identity": "2.5.4.15=pytest,CN=Tester"
        })
    }))

    response = await pki_rpcclient.revoke_certificate(
        "test", serial_number, "superseded")
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "Notification",
        "description": "Certificate was revoked.",
        "body": None
    }))

    response = await pki_rpcclient.get_certificate("test", serial_number)
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "CertificateInfo",
        "body": hamcrest.has_entries({
            "account": "test",
            "status": "revoked",
            "serial_number": serial_number,
            "fingerprint": hamcrest.instance_of(str),
            "valid_from": hamcrest.instance_of(datetime),
            "valid_until": hamcrest.instance_of(datetime),
            "generation_date": hamcrest.instance_of(datetime),
            "revocation_date": hamcrest.instance_of(datetime),
            "revocation_reason": "superseded",
            "identity": "2.5.4.15=pytest,CN=Tester"
        })
    }))

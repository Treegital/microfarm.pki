import asyncio
import pytest
import time
import hamcrest
from freezegun import freeze_time
from datetime import datetime
from freezegun import freeze_time
from branding_iron.identity import Identity
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp, load_pem_x509_certificates, ReasonFlags


async def tear_down(event_loop):
    tasks = asyncio.all_tasks(event_loop)
    tasks = [t for t in tasks if not t.done()]
    for task in tasks:
        task.cancel()
    try:
        await asyncio.wait(tasks)
    except asyncio.exceptions.CancelledError:
        pass


@pytest.mark.asyncio
async def test_request_certificate(
        service, pki_rpcservice, pki_rpcclient, pki_responder, minter, event_loop):

    response = await pki_rpcclient.list_requests("test")
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "PaginatedSet[CertificateRequest]",
        "description": None,
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
    assert response == {
        "code": 200,
        "type": "PaginatedSet[CertificateInfo]",
        "description": None,
        "body": {
            "metadata": {
                "total": 0,
                "offset": None,
                "page_size": None
            },
            "items": ()
        }
    }

    identity = Identity(
        common_name="Tester",
        business_category="pytest"
    )

    with freeze_time("2023-10-01 12:00:00"):
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
            "submission_date": datetime(2023, 10, 1, 12, 0, 0),
            "generation_date": None,
            "serial_number": None
        })
    }))

    task = service.tasks[request_id]
    assert task.done() is False

    with freeze_time("2023-10-02 15:12:00"):
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
            "submission_date": datetime(2023, 10, 1, 12, 0, 0),
            "generation_date": datetime(2023, 10, 2, 15, 12, 0),
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
                    "submission_date": datetime(2023, 10, 1, 12, 0, 0),
                    "generation_date": datetime(2023, 10, 2, 15, 12, 0),
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
                    "valid_from": datetime(2023, 9, 30, 2, 0, 0),
                    "valid_until": datetime(2025, 10, 2, 1, 59, 59),
                    "generation_date": datetime(2023, 10, 2, 15, 12, 0),
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
            "valid_from": datetime(2023, 9, 30, 2, 0, 0),
            "valid_until": datetime(2025, 10, 2, 1, 59, 59),
            "generation_date": datetime(2023, 10, 2, 15, 12, 0),
            "revocation_date": None,
            "revocation_reason": None,
            "identity": "2.5.4.15=pytest,CN=Tester"
        })
    }))

    with freeze_time("2026-10-01 12:00:00"):
        response = await pki_rpcclient.get_certificate("test", serial_number)
        hamcrest.assert_that(response, hamcrest.has_entries({
            "code": 200,
            "type": "CertificateInfo",
            "description": "Account certificate info",
            "body": hamcrest.has_entries({
                "account": "test",
                "status": "inactive",
                "serial_number": serial_number,
                "fingerprint": hamcrest.instance_of(str),
                "valid_from": datetime(2023, 9, 30, 0, 0, 0),
                "valid_until": datetime(2025, 10, 1, 23, 59, 59),
                "generation_date": datetime(2023, 10, 2, 15, 12, 0),
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

    response = await pki_rpcclient.get_certificate_pem("test", serial_number)
    hamcrest.assert_that(response, hamcrest.has_entries({
        "code": 200,
        "type": "PEM",
        "description": "Certificate chain",
        "body": hamcrest.instance_of(bytes)
    }))

    certs = load_pem_x509_certificates(response['body'])
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(certs[0], certs[1], hashes.SHA256())
    req = builder.build()
    data = req.public_bytes(serialization.Encoding.DER)

    responder = asyncio.ensure_future(pki_responder, loop=event_loop)
    response = await pki_rpcclient.certificate_ocsp(data)
    hamcrest.assert_that(response, hamcrest.has_entries({
        'body': hamcrest.instance_of(bytes),
        'code': 200,
        'description': 'OCSP Response',
        'type': 'DER'
    }))
    responder.cancel()

    decoded = ocsp.load_der_ocsp_response(response['body'])
    assert decoded.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert decoded.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert decoded.revocation_time is not None
    assert decoded.revocation_reason == ReasonFlags.superseded
    await tear_down(event_loop)

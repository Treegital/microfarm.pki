from peewee import Case, Value
from datetime import datetime
from .models import Request, Certificate, ReasonFlags
from microfarm_pki.utils import date2ts, current_ts, strdate2ts


def create_certificate(request_id, **data):
    # We translate datetime to timestamp
    data['valid_from'] = strdate2ts(data['valid_from'])
    data['valid_until'] = strdate2ts(data['valid_until'])
    return Certificate.create(request_id=request_id, **data)


def get_base_query():
    now = Value(current_ts())
    certificate_status = Case(None, [
        (Certificate.revocation_date, 'revoked'),
        (
            now.between(
                Certificate.valid_from, Certificate.valid_until
            ), 'active'
        )
    ], 'inactive')

    return (
        Certificate.select(
            Certificate.account,
            Certificate.serial_number,
            Certificate.fingerprint,
            Certificate.valid_from,
            Certificate.valid_until,
            Certificate.generation_date,
            Certificate.revocation_date,
            Certificate.revocation_reason.cast('CHAR'),
            Request.identity,
            certificate_status.alias("status")
        )
        .join(Request)
    )


def get_certificate(serial_number: str, account: str | None = None):
    query = (
        get_base_query()
        .where(Certificate.serial_number == serial_number)
    )
    if account:
        return query.where(Certificate.account == account)
    return query


def get_certificates(account: str | None = None):
    query = get_base_query()
    if account:
        return query.where(Certificate.account == account)
    return query


def get_valid_certificates(account: str | None = None):
    now = Value(current_ts())
    return (
        Certificate.select(
            Certificate.account,
            Certificate.serial_number,
            Certificate.fingerprint,
            Certificate.valid_from,
            Certificate.valid_until,
            Certificate.generation_date,
            Request.identity
        )
        .join(Request).where(
            now.between(
                Certificate.valid_from, Certificate.valid_until
            ),
            Certificate.revocation_date.is_null()
        )
    )


def revoke_certificate(
        serial_number: str, reason: str, account: str | None = None):

    ts = current_ts()
    now = Value(ts)
    query = (
        Certificate.update({
            Certificate.revocation_date: ts,
            Certificate.revocation_reason: ReasonFlags[reason]
        })
        .where(
            Certificate.serial_number == serial_number,
            Certificate.revocation_date.is_null(),
            now.between(
                Certificate.valid_from, Certificate.valid_until
            )
        )
    )
    if account:
        return query.where(Certificate.account == account)
    return query


def get_certificate_pem(serial_number: str, account: str | None = None):
    return (
        Certificate.select(
            Certificate.pem_cert,
            Certificate.pem_chain,
            Certificate.revocation_date,
            Certificate.revocation_reason.cast('CHAR')
        ).where(
            Certificate.serial_number == serial_number
        )
    )
    if account:
        return query.where(Certificate.account == account)
    return query


def get_valid_certificate_pem(serial_number: str, account: str | None = None):

    now = Value(current_ts())
    return (
        Certificate.select(
            Certificate.pem_cert,
            Certificate.pem_chain,
            Certificate.pem_private_key
        ).where(
            Certificate.serial_number == serial_number,
            Certificate.revocation_date.is_null(),
            now.between(
                Certificate.valid_from, Certificate.valid_until
            )
        )
    )
    if account:
        return query.where(Certificate.account == account)
    return query

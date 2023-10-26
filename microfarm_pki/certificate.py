from peewee import JOIN, SQL, Case
from .models import Request, Certificate


def get_base_query():
    now = SQL("CURRENT_TIMESTAMP")
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


def account_certificate(account: str, serial_number: str):
    return (
        get_base_query()
        .where(Certificate.serial_number == serial_number,
               Certificate.account == account)
    )


def account_certificates(account: str):
    return (
        get_base_query()
        .where(Certificate.account == account)
    )

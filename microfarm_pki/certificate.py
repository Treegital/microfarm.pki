from peewee import SQL, Case
from .models import Request, Certificate, ReasonFlags


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


def revoke_account_certificate(
        account: str, serial_number: str, reason: str):

    return (
        Certificate.update({
            Certificate.revocation_date: SQL('CURRENT_TIMESTAMP'),
            Certificate.revocation_reason: ReasonFlags[reason]
        })
        .where(
            Certificate.account == account,
            Certificate.serial_number == serial_number,
            Certificate.revocation_date.is_null()
        )
    )


def account_certificate_pem(account: str, serial_number: str):
    return (
        Certificate.select(
            Certificate.pem_cert,
            Certificate.pem_chain,
            Certificate.revocation_date,
            Certificate.revocation_reason.cast('CHAR')
        ).where(
            Certificate.serial_number == serial_number,
            Certificate.account == account
        )
    )


def certificate_pem(serial_number: str):
    return (
        Certificate.select(
            Certificate.pem_cert,
            Certificate.pem_chain,
            Certificate.revocation_date,
            Certificate.revocation_reason.cast('CHAR')
        ).where(
            Certificate.serial_number == serial_number,
        )
    )


def account_certificates(account: str):
    return (
        get_base_query()
        .where(Certificate.account == account)
    )

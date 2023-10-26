from peewee import JOIN, Case
from .models import Request, Certificate


def get_base_query():
    request_status = Case(None, [
        (Certificate.generation_date, 'generated'),
    ], 'pending')

    return (
        Request.select(
            Request.id,
            Request.identity,
            Request.requester,
            Request.submission_date,
            Certificate.serial_number,
            Certificate.generation_date
        )
        .join(Certificate, JOIN.LEFT_OUTER)
    )


def account_request(account: str, request_id: str):
    return get_base_query().where(
        Request.requester == account,
        Request.id == request_id
    )


def account_requests(account: str):
    return get_base_query().where(
        Request.requester == account
    )

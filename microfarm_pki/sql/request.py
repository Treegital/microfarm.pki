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
            Certificate.generation_date,
            request_status.alias('status')
        )
        .join(Certificate, JOIN.LEFT_OUTER)
    )


def create_request(id: str, requester: str, identity: str):
    return Request.create(id=id, requester=requester, identity=identity)


def get_request(request_id: str, account: str | None = None):
    query = get_base_query().where(Request.id == request_id)
    if account:
        return query.where(Request.requester == account)
    return query


def get_requests(account: str | None = None):
    query = get_base_query()
    if account:
        return query.where(Request.requester == account)
    return query

from datetime import datetime, timezone
from calendar import timegm


def date2ts(date: datetime):
    return timegm(date.utctimetuple())


def strdate2ts(date: str):
    # Translate a datetime expressed as string to a timestamp
    # The format is fixed.
    return date2ts(datetime.strptime(date, '%Y-%m-%dT%H:%M:%S'))


def current_date():
    # Separate method to facilitate testing
    return datetime.now(timezone.utc)


def current_ts():
    # Separate method to facilitate testing
    return date2ts(datetime.now(timezone.utc))

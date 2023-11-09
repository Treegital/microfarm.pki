import typing as t
from typing_extensions import TypedDict
from peewee import Ordering


class ColumnSorting(TypedDict):
    key: str
    order: t.Literal['asc'] | t.Literal['desc']


Sorting = t.Iterable[ColumnSorting]


def resolve_order_by(model, ordering: Sorting) -> t.Iterator[Ordering]:
    for column_order in ordering:
        sort_field = getattr(model, column_order['key'])
        if column_order['order'] == 'asc':
            yield sort_field.asc()
        elif column_order['order'] == 'desc':
            yield sort_field.desc()
        else:
            raise NameError(column_order['order'])


def sort(query, order_by: t.Iterable[Ordering]):
    for ordering in order_by:
        query = query.order_by(ordering)
    return query


def paginate(query, offset: int = 0, limit: int = 0):
    if offset:
        query = query.offset(offset)

    if limit:
        query = query.limit(limit)

    return query

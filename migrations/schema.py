"""
Keep the database schema in sync with models.py.

``db.create_all()`` creates missing tables but never alters existing ones, so
databases created by older versions miss columns added later (for example
``scan_sessions.total_ips``). ``sync_schema`` adds those columns with
``ALTER TABLE ... ADD COLUMN``, which works on both SQLite and PostgreSQL.
It is idempotent and safe to run on every start.
"""
import logging
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)


def _column_default_sql(column, dialect):
    """Return a SQL DEFAULT clause for simple scalar Python defaults, else ''."""
    default = column.default
    if default is None or not default.is_scalar:
        return ''
    value = default.arg
    if isinstance(value, bool):
        if dialect.name == 'postgresql':
            return ' DEFAULT TRUE' if value else ' DEFAULT FALSE'
        return ' DEFAULT 1' if value else ' DEFAULT 0'
    if isinstance(value, (int, float)):
        return f' DEFAULT {value}'
    if isinstance(value, str):
        escaped = value.replace("'", "''")
        return f" DEFAULT '{escaped}'"
    return ''


def sync_schema(db):
    """Create missing tables and add missing nullable columns. Returns the list of added columns."""
    db.create_all()
    engine = db.engine
    inspector = inspect(engine)
    quote = engine.dialect.identifier_preparer.quote
    added = []

    with engine.begin() as conn:
        for table in db.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {col['name'] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                if column.primary_key:
                    logger.error(f"Cannot add primary key column {table.name}.{column.name}; skipping")
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                default_sql = _column_default_sql(column, engine.dialect)
                conn.execute(text(
                    f'ALTER TABLE {quote(table.name)} ADD COLUMN {quote(column.name)} {col_type}{default_sql}'
                ))
                added.append(f"{table.name}.{column.name}")
                logger.info(f"Added missing column {table.name}.{column.name}")

    return added

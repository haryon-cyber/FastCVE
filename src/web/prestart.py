"""
Pre-start hook for the FastCVE app container.

Ensures environment is loaded and DB schema is migrated to the latest Alembic head
before the web server starts.
"""

from common.util import ensure_db_schema


def main() -> None:
    ensure_db_schema()


if __name__ == "__main__":
    main()

"""
Generic utility functions for the fastcve.

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

import os
import shutil
import time
from alembic.config import Config
from alembic import command


class ValidationError(Exception): ...


# ------------------------------------------------------------------------------
# create/update the db schema using alembic
def init_db_schema():

    # ------------------------------------------------------------------------------
    home = os.environ.get("FCDB_HOME")
    if not home:
        raise ValidationError(f'Project home environment vars not properly set: {home}')

    working_dir = os.path.join(home, 'db')
    cwd = os.getcwd()

    os.chdir(working_dir)
    try:
        from sqlalchemy import text
        from generic import ApplicationContext

        appctx = ApplicationContext.instance()

        # Prevent concurrent migration runs (uvicorn workers, CLI execs, etc).
        # Use a fixed lock id (int64) scoped to this DB instance.
        lock_id = int(os.environ.get("FCDB_ALEMBIC_LOCK_ID", "864205"))

        with appctx.db.engine.connect() as connection:
            connection.execute(text("SELECT pg_advisory_lock(:lock_id)"), {"lock_id": lock_id})
            try:
                alembic_cfg = Config("alembic.ini")
                # Runs only pending migrations; it's a no-op when already at head.
                command.upgrade(alembic_cfg, "head")
            finally:
                connection.execute(text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": lock_id})
    finally:
        os.chdir(cwd)


# ------------------------------------------------------------------------------
def ensure_db_schema(max_attempts=60, retry_delay=1):

    setup_env()

    last_exc = None
    for attempt in range(max_attempts):
        try:
            init_db_schema()
            return
        except Exception as exc:  # pragma: no cover
            last_exc = exc
            if attempt == max_attempts - 1:
                break
            time.sleep(retry_delay)

    if last_exc is not None:  # pragma: no cover
        raise last_exc


# ------------------------------------------------------------------------------
def setup_env():

    import subprocess

    home = os.environ.get("FCDB_HOME")
    if not home:
        raise ValidationError(f'Project home environment vars not properly set: {home}')

    shell = shutil.which("bash") or shutil.which("sh")
    if not shell:
        raise ValidationError("Neither 'bash' nor 'sh' found in PATH; cannot run setenv.sh")

    # Run the setenv script that exports needed environment variables
    script = os.path.join(home, 'config', 'setenv.sh')
    result = subprocess.run([shell, script], stdout=subprocess.PIPE, universal_newlines=True)

    # Parse the output to extract the environment variables
    for line in result.stdout.split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            os.environ[key] = value

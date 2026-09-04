"""Empty the Oracle CI schema so a test run starts from a known-clean state.

Django isolates Oracle runs by creating a throwaway user and tablespace and
dropping them again afterwards. The CI schema is instead pre-created with the
minimum set of privileges (see docs/contributing.rst), so
``tests/oracle_settings.py`` turns ``TEST['CREATE_USER']`` and
``TEST['CREATE_DB']`` off -- which also means Django tears nothing down at the
end of a run. Tables would then survive into the next run and ``migrate`` would
fail with ORA-00955 ("name is already used by an existing object"), or worse,
succeed against a schema left over from an older migration graph.

Dropping objects you own needs no privilege beyond owning them, so this runs
happily as the limited CI user. It is wired in as ``commands_pre`` of the
``*-ora21`` tox environments.
"""

import os
import sys


# Objects are dropped in dependency order: tables (taking their indexes,
# constraints and identity sequences with them), then anything a table could
# still have depended on.
_DROP_PLAN = (
    ("SELECT table_name FROM user_tables WHERE nested = 'NO'", 'DROP TABLE "{}" CASCADE CONSTRAINTS PURGE'),
    ("SELECT view_name FROM user_views", 'DROP VIEW "{}" CASCADE CONSTRAINTS'),
    ("SELECT sequence_name FROM user_sequences", 'DROP SEQUENCE "{}"'),
    ("SELECT trigger_name FROM user_triggers", 'DROP TRIGGER "{}"'),
    (
        "SELECT object_name FROM user_objects WHERE object_type = 'PROCEDURE'",
        'DROP PROCEDURE "{}"',
    ),
    ("SELECT object_name FROM user_objects WHERE object_type = 'FUNCTION'", 'DROP FUNCTION "{}"'),
    ("SELECT object_name FROM user_objects WHERE object_type = 'PACKAGE'", 'DROP PACKAGE "{}"'),
    ("SELECT type_name FROM user_types", 'DROP TYPE "{}" FORCE'),
)


def reset_schema(alias: str = "default") -> int:
    """Drop every object owned by the connected user. Return how many were dropped."""
    from django.db import connections

    connection = connections[alias]
    dropped = 0
    with connection.cursor() as cursor:
        for query, template in _DROP_PLAN:
            cursor.execute(query)
            # Recycle-bin entries surface as BIN$... objects; PURGE clears those in
            # one go below rather than dropping them one by one.
            names = [row[0] for row in cursor.fetchall() if not row[0].startswith("BIN$")]
            for name in names:
                # Oracle cannot bind an identifier as a parameter, and these names come
                # straight out of the connected user's own data dictionary, so there is
                # no untrusted input to interpolate here.
                cursor.execute(template.format(name.replace('"', '""')))
                dropped += 1
        cursor.execute("PURGE RECYCLEBIN")
    connection.close()
    return dropped


def main() -> int:
    import django

    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE")
    if not settings_module:
        print("DJANGO_SETTINGS_MODULE is not set; refusing to guess which schema to empty.")
        return 2
    django.setup()

    from django.db import connections

    if connections["default"].vendor != "oracle":
        print(f"{settings_module} is not an Oracle configuration; nothing to reset.")
        return 0

    dropped = reset_schema()
    user = connections["default"].settings_dict["USER"]
    print(f"Reset Oracle schema {user}: dropped {dropped} object(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

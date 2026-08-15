"""Store Discord snowflake guild IDs in guild-scoped tables.

The application consistently uses Discord guild snowflakes as ``guild_id``.
Earlier migrations incorrectly declared those columns as internal INTEGER
foreign keys to ``guilds.id``.
"""

from alembic import op


revision = "0012_guild_id_bigint"
down_revision = "0011_permission_enforcement"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE constraint_name text;
        BEGIN
            FOR constraint_name IN
                SELECT con.conname
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_attribute att ON att.attrelid = rel.oid
                    AND att.attnum = ANY(con.conkey)
                WHERE con.contype = 'f'
                  AND att.attname = 'guild_id'
                  AND rel.relname IN (
                      'security_configs', 'security_roles', 'security_channels',
                      'user_capabilities', 'security_snapshots', 'security_event_logs',
                      'security_incidents', 'recovery_actions',
                      'ai_threat_assessments', 'admin_changes'
                  )
            LOOP
                EXECUTE format(
                    'ALTER TABLE %I DROP CONSTRAINT %I',
                    (SELECT relname FROM pg_class r JOIN pg_constraint c ON c.conrelid = r.oid WHERE c.conname = constraint_name LIMIT 1),
                    constraint_name
                );
            END LOOP;
        END $$;
        """
    )
    for table in (
        "security_configs",
        "security_roles",
        "security_channels",
        "user_capabilities",
        "security_snapshots",
        "security_event_logs",
        "security_incidents",
        "recovery_actions",
        "ai_threat_assessments",
        "admin_changes",
    ):
        op.execute(f"ALTER TABLE {table} ALTER COLUMN guild_id TYPE BIGINT")


def downgrade() -> None:
    raise RuntimeError("Downgrade is unsafe because Discord snowflake IDs do not fit INTEGER")

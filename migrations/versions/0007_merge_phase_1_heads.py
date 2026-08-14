"""Merge the two existing Phase 1 migration heads.

Both permission-enforcement and AI threat-assessment migrations were added
against 0005_recovery_actions. This merge revision preserves existing
migration history while restoring a single Alembic head for fresh and
existing deployments.
"""

revision = "0007_merge_phase_1_heads"
down_revision = ("0006_ai_threat_assessments", "0006_permission_enforcement")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

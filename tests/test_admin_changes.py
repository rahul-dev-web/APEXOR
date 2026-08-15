from app.models.admin_changes import AdminChange


def test_admin_change_model_is_a_durable_control_plane_audit_record() -> None:
    columns = AdminChange.__table__.c

    assert {"guild_id", "actor_discord_id", "action", "target_discord_id", "capability", "metadata_json", "created_at"} <= set(columns.keys())
    assert columns.guild_id.index is True
    assert columns.actor_discord_id.index is True
    assert columns.action.index is True
    assert columns.created_at.index is True

from dataclasses import dataclass

from app.security.recovery import RecoveryEngine


@dataclass(frozen=True)
class FakeTarget:
    id: int


class FakeGuild:
    def __init__(self, roles=None, members=None):
        self.roles = roles or {}
        self.members = members or {}

    def get_role(self, role_id):
        return self.roles.get(role_id)

    def get_member(self, member_id):
        return self.members.get(member_id)


def test_resolve_overwrites_uses_recreated_role_id():
    recreated_role = FakeTarget(id=9002)
    guild = FakeGuild(roles={9002: recreated_role})

    overwrites = RecoveryEngine._resolve_overwrites(
        guild,
        [
            {
                "target_id": 1001,
                "target_type": "role",
                "allow": 1024,
                "deny": 2048,
            }
        ],
        restored_ids={1001: 9002},
    )

    assert list(overwrites.keys()) == [recreated_role]
    permission = overwrites[recreated_role]
    allow, deny = permission.pair()
    assert allow.value == 1024
    assert deny.value == 2048


def test_resolve_overwrites_skips_missing_dependency():
    guild = FakeGuild()

    overwrites = RecoveryEngine._resolve_overwrites(
        guild,
        [
            {
                "target_id": 1001,
                "target_type": "role",
                "allow": 1024,
                "deny": 0,
            }
        ],
        restored_ids={1001: 9002},
    )

    assert overwrites == {}


def test_resolve_overwrites_maps_member_targets_without_role_collision():
    member = FakeTarget(id=7007)
    guild = FakeGuild(members={7007: member})

    overwrites = RecoveryEngine._resolve_overwrites(
        guild,
        [
            {
                "target_id": 7001,
                "target_type": "member",
                "allow": 8,
                "deny": 16,
            }
        ],
        restored_ids={7001: 7007},
    )

    assert list(overwrites.keys()) == [member]
    allow, deny = overwrites[member].pair()
    assert allow.value == 8
    assert deny.value == 16


def test_resolve_overwrites_preserves_multiple_targets():
    role = FakeTarget(id=9002)
    member = FakeTarget(id=7007)
    guild = FakeGuild(roles={9002: role}, members={7007: member})

    overwrites = RecoveryEngine._resolve_overwrites(
        guild,
        [
            {"target_id": 1001, "target_type": "role", "allow": 1024, "deny": 0},
            {"target_id": 2001, "target_type": "member", "allow": 8, "deny": 16},
        ],
        restored_ids={1001: 9002, 2001: 7007},
    )

    assert set(overwrites) == {role, member}

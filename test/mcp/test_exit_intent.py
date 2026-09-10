import pytest

from fakenet.mcp.exit_intent import StopIntent, claim, notification


@pytest.fixture
def scene(tmp_path):
    identity = dict(run_id='run-a', pid=73, creation_time='123456',
                    supervisor_pid=70, supervisor_creation_time='123000',
                    supervisor_instance='instance-a')
    now = [10.0]
    owner = StopIntent(tmp_path, identity, clock=lambda: now[0])
    observed = notification(['73', '73', '99', '0'])
    return tmp_path, identity, now, owner, observed


def test_claim_requires_live_acceptance_and_is_single_use(scene):
    path, identity, now, owner, observed = scene
    issued = owner.publish(20)
    first = claim(path, identity, observed, now[0])
    assert first == issued
    assert claim(path, identity, observed, now[0]) is None
    assert owner.accept_normal(first, observed)
    assert owner.normal_is_valid(first)
    assert not owner.accept_normal(first, observed)
    owner.invalidate()
    assert not owner.normal_is_valid(first)


@pytest.mark.parametrize('change', [dict(initiator_pid=74), dict(exit_status=1),
                                   dict(target_pid=74)])
def test_external_zero_or_abnormal_exit_never_claims(scene, change):
    path, identity, now, owner, observed = scene
    owner.publish(20)
    observed.update(change)
    assert claim(path, identity, observed, now[0]) is None


@pytest.mark.parametrize('field,value', [('run_id', 'other'), ('creation_time', '123457'),
                                       ('supervisor_instance', 'restarted')])
def test_mismatched_lifetime_cannot_claim(scene, field, value):
    path, identity, now, owner, observed = scene
    owner.publish(20)
    assert claim(path, dict(identity, **{field: value}), observed, now[0]) is None


def test_invalidation_after_helper_claim_cannot_waive_dump(scene):
    path, identity, now, owner, observed = scene
    owner.publish(20)
    first = claim(path, identity, observed, now[0])
    owner.invalidate()
    assert not owner.accept_normal(first, observed)


def test_claim_from_previous_attempt_cannot_authorize_retry(scene):
    path, identity, now, owner, observed = scene
    old = owner.publish(20)
    owner.invalidate()
    current = owner.publish(20)
    assert current['sequence'] > old['sequence']
    assert current['nonce'] != old['nonce']
    assert not owner.accept_normal(old, observed)


def test_grace_expiry_rejects_both_claim_and_final_acceptance(scene):
    path, identity, now, owner, observed = scene
    issued = owner.publish(20)
    now[0] = 20
    assert claim(path, identity, observed, now[0]) is None
    assert not owner.accept_normal(issued, observed)


def test_restart_cannot_recover_live_authority_from_existing_file(scene):
    path, identity, now, owner, observed = scene
    issued = owner.publish(20)
    restarted = StopIntent(path, identity, clock=lambda: now[0])
    assert not restarted.accept_normal(issued, observed)


def test_unexpected_zero_exit_without_intent_cannot_claim(scene):
    path, identity, now, owner, observed = scene
    assert claim(path, identity, observed, now[0]) is None


@pytest.mark.parametrize('args', [[], ['1', '2', '3', '-1'], ['1', '2', '3', '4294967296'],
                                 ['1', '2', '3', '0x10'], ['0', '2', '3', '0'],
                                 ['1', '2', '3', '０'], ['1', '2', '3', '0', '/path']])
def test_notification_rejects_non_os_argument_shapes(args):
    with pytest.raises(ValueError):
        notification(args)


def test_maximum_dword_exit_code_is_valid():
    assert notification(['1', '2', '3', '4294967295'])['exit_status'] == 0xffffffff

"""Recovery consent, timing, flapping and failure-path regressions; no network changes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auto_return import AutoReturn, new_window, ready, sample


class FakeGateway:
    def __init__(self, directory):
        self.settings = Path(directory)
        self.mode_path = self.settings / 'mode'
        self.activation_path = self.settings / 'activation.json'
        self.config = self.settings / 'config.json'
        self.mode_path.write_text('rules')
        self.activation_path.write_text('{"confirmed":true}')
        self.config.write_text('{}')
        (self.settings / 'awg-outbound.json').write_text('{}')
        self.fingerprint = 'confirmed-policy'
        self.probe_ok = True
        self.confirm_ok = True
        self.calls = []
        self.auto_return = AutoReturn(self)

    def probe(self):
        return self.probe_ok

    def probe_uplink(self):
        self.calls.append('isolated_probe')
        return self.probe_ok

    def build(self, mode):
        return {}

    def check_readiness(self, config):
        pass

    def recovery_fingerprint(self):
        return self.fingerprint

    def public(self, transition=None):
        return {'mode': self.mode_path.read_text(), 'auto_return': self.auto_return.status(),
                'transition': transition}

    def rules(self, seconds, automatic):
        self.calls.append(('rules', automatic))
        self.mode_path.write_text('rules')

    def confirm(self, automatic):
        self.calls.append(('confirm', automatic))
        if not self.confirm_ok:
            raise RuntimeError('Main gateway failed after return')

    def direct(self, reason, automatic):
        self.auto_return.rollback(reason, automatic, {'confirmed': False})
        self.calls.append('direct')
        self.mode_path.write_text('direct')


class AutoReturnTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.g = FakeGateway(self.directory.name)
        self.now = 1000
        self.boot = 'boot-one'
        self.patcher = patch('auto_return.clock', side_effect=lambda: (self.now, self.boot))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def arm_and_rollback(self):
        self.g.auto_return.enable()
        self.g.auto_return.rollback('connectivity_failed', True, {'confirmed': True})
        self.g.mode_path.write_text('direct')

    def stable_checks(self):
        for _ in range(6):
            self.g.auto_return.watch()
            self.now += 61

    def test_disabled_by_default_and_no_initial_auto_activation(self):
        self.g.mode_path.write_text('direct')
        self.g.auto_return.watch()
        self.assertFalse(self.g.auto_return.status()['enabled'])
        self.assertEqual(self.g.calls, [])
        with self.assertRaises(RuntimeError):
            self.g.auto_return.enable()

    def test_enable_requires_confirmed_healthy_live_policy(self):
        self.g.activation_path.write_text('{"confirmed":false}')
        with self.assertRaises(RuntimeError):
            self.g.auto_return.enable()
        self.g.activation_path.write_text('{"confirmed":true}')
        self.g.config.write_text('{"different":true}')
        with self.assertRaises(RuntimeError):
            self.g.auto_return.enable()

    def test_six_checks_over_five_minutes_then_separate_activation_tick(self):
        self.arm_and_rollback()
        self.stable_checks()
        self.assertNotIn(('rules', True), self.g.calls)
        self.g.auto_return.watch()
        self.assertEqual(self.g.mode_path.read_text(), 'rules')
        self.assertEqual(self.g.calls[-2:], [('rules', True), ('confirm', True)])
        self.assertFalse(self.g.auto_return.state['pending'])
        self.assertEqual(self.g.auto_return.status()['attempts'], 1)

    def test_frequent_watch_ticks_cannot_accelerate_checks(self):
        self.arm_and_rollback()
        for _ in range(20):
            self.g.auto_return.watch()
            self.now += 1
        self.assertEqual(self.g.calls, ['isolated_probe'])
        self.assertEqual(self.g.auto_return.status()['successful_checks'], 1)

    def test_one_failure_or_long_gap_resets_stability_window(self):
        self.arm_and_rollback()
        self.stable_checks()
        # A stale healthy window cannot authorize activation after a long pause.
        self.now += 300
        self.g.probe_ok = False
        self.g.auto_return.watch()
        self.assertEqual(self.g.auto_return.status()['successful_checks'], 0)
        self.assertFalse(ready(self.g.auto_return.state, self.now))
        self.g.probe_ok = True
        self.now += 61
        self.g.auto_return.watch()
        self.assertEqual(self.g.auto_return.status()['successful_checks'], 1)

    def test_manual_direct_trial_timeout_and_unconfirmed_failure_disarm(self):
        for reason, automatic, confirmed in [('manual_direct', False, True),
                                             ('confirmation_timeout', True, False),
                                             ('connectivity_failed', True, False)]:
            with self.subTest(reason=reason, confirmed=confirmed):
                self.g.auto_return.enable()
                self.g.auto_return.rollback(reason, automatic, {'confirmed': confirmed})
                self.assertFalse(self.g.auto_return.status()['enabled'])

    def test_policy_or_runtime_change_cancels_automatic_return(self):
        self.arm_and_rollback()
        self.g.fingerprint = 'unapproved-edit'
        self.g.auto_return.watch()
        self.assertFalse(self.g.auto_return.status()['enabled'])
        self.assertEqual(self.g.calls, [])

    def test_state_survives_process_restart_but_not_old_boot_samples(self):
        self.arm_and_rollback()
        self.stable_checks()
        self.g.auto_return = AutoReturn(self.g)
        self.boot = 'boot-two'
        self.now = 15
        self.g.auto_return.watch()
        self.assertNotIn(('rules', True), self.g.calls)
        self.assertEqual(self.g.auto_return.status()['successful_checks'], 1)

    def test_failed_main_confirmation_restores_direct_and_backs_off(self):
        self.arm_and_rollback()
        self.stable_checks()
        self.g.confirm_ok = False
        self.g.auto_return.watch()
        self.assertEqual(self.g.mode_path.read_text(), 'direct')
        self.assertTrue(self.g.auto_return.state['pending'])
        self.assertEqual(self.g.auto_return.status()['cooldown_remaining_seconds'], 900)
        calls = list(self.g.calls)
        self.now += 899
        self.g.auto_return.watch()
        self.assertEqual(self.g.calls, calls)

    def test_repeated_outages_back_off_up_to_one_hour(self):
        self.arm_and_rollback()
        for expected in (900, 1800, 3600, 3600):
            self.g.auto_return.schedule_retry()
            self.assertEqual(self.g.auto_return.status()['cooldown_remaining_seconds'], expected)
        self.g.mode_path.write_text('rules')
        self.g.auto_return.active(True)
        self.now += 1800
        self.g.auto_return.active(True)
        self.assertEqual(self.g.auto_return.state['attempts'], 0)

    def test_recovery_does_not_read_wall_clock_for_stability(self):
        self.arm_and_rollback()
        with patch('auto_return.time.time', return_value=9999999999):
            self.g.auto_return.watch()
        self.assertEqual(self.g.auto_return.status()['successful_checks'], 1)
        self.assertNotIn(('rules', True), self.g.calls)

    def test_probe_success_count_alone_is_insufficient(self):
        state = {}
        new_window(state, 0, 'boot')
        for second in range(6):
            sample(state, True, second)
        self.assertFalse(ready(state, 5))


if __name__ == '__main__':
    unittest.main()

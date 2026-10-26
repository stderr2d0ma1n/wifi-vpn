"""Opt-in return to an unchanged, owner-confirmed AWG policy after an outage."""
import json
from pathlib import Path
import time

INTERVAL = 60
STABLE_SECONDS = 300
SUCCESSES = 6
RESET_AFTER = 1800


def clock():
    return time.monotonic(), Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def new_window(state, now, boot, cooldown=0):
    state.update(boot_id=boot, retry_after=now + cooldown, successes=0,
                 stable_since=None, last_probe=None, last_probe_ok=None)


def ready(state, now):
    return (state.get('successes', 0) >= SUCCESSES and
            state.get('stable_since') is not None and
            now - state['stable_since'] >= STABLE_SECONDS and
            state.get('last_probe') is not None and
            0 <= now - state['last_probe'] <= INTERVAL * 2)


def sample(state, ok, now):
    previous = state.get('last_probe')
    if previous is None or not 0 <= now - previous <= INTERVAL * 2:
        state.update(successes=0, stable_since=None)
    state.update(last_probe=now, last_probe_ok=ok)
    if not ok:
        state.update(successes=0, stable_since=None)
    else:
        if state.get('stable_since') is None:
            state['stable_since'] = now
        state['successes'] = state.get('successes', 0) + 1


class AutoReturn:
    def __init__(self, gateway):
        self.gateway = gateway
        self.path = gateway.settings / 'auto-return.json'
        try:
            self.state = json.loads(self.path.read_text())
            if not isinstance(self.state, dict):
                raise ValueError('Invalid state')
        except FileNotFoundError:
            self.state = {}
        except (OSError, ValueError):
            self.state = {'disabled_reason': 'invalid_auto_return_state'}

    def save(self):
        # Imported here to keep the state machine independent of the gateway module.
        from gateway_safety import atomic
        atomic(self.path, self.state)

    def disable(self, reason):
        self.state = {'enabled': False, 'pending': False, 'disabled_reason': reason}
        self.save()

    def enable(self):
        g = self.gateway
        from gateway_safety import load
        if (g.mode_path.read_text().strip() != 'rules' or
                not load(g.activation_path, {}).get('confirmed') or not g.probe()):
            raise RuntimeError('Enable auto-return only for a healthy owner-confirmed VPN')
        if not (g.settings / 'awg-outbound.json').exists():
            raise RuntimeError('Auto-return requires the prepared native AWG uplink')
        g.check_readiness(g.build('rules'))
        if json.loads(g.config.read_text()) != g.build('rules'):
            raise RuntimeError('Live VPN differs from the confirmed candidate')
        now, boot = clock()
        self.state = {'enabled': True, 'pending': False, 'fingerprint': g.recovery_fingerprint(),
                      'authorized_at': int(time.time()), 'attempts': 0, 'active_since': now}
        new_window(self.state, now, boot)
        self.save()
        return g.public({'kind': 'auto_return_enabled', 'reason': 'owner_authorized'})

    def matches(self):
        try:
            return self.state.get('fingerprint') == self.gateway.recovery_fingerprint()
        except (OSError, ValueError, KeyError, RuntimeError):
            return False

    def rollback(self, reason, automatic, activation):
        if not self.state.get('enabled'):
            return
        if (automatic and self.state.get('pending') and
                reason == 'main_service_failed_while_direct'):
            return
        if (not automatic or reason != 'connectivity_failed' or
                not activation.get('confirmed') or not self.matches()):
            self.disable(reason)
            return
        self.schedule_retry()

    def schedule_retry(self):
        now, boot = clock()
        attempts = min(self.state.get('attempts', 0) + 1, 5)
        cooldown = 0 if attempts == 1 else min(900 * 2 ** (attempts - 2), 3600)
        self.state.update(enabled=True, pending=True, attempts=attempts, active_since=None)
        new_window(self.state, now, boot, cooldown)
        self.save()

    def active(self, ok):
        if not self.state.get('enabled'):
            return
        if not self.matches():
            self.disable('policy_or_runtime_changed')
            return
        now, boot = clock()
        if self.state.get('boot_id') != boot or not ok:
            self.state.update(boot_id=boot, active_since=None)
        if ok:
            if self.state.get('active_since') is None:
                self.state['active_since'] = now
            if now - self.state['active_since'] >= RESET_AFTER:
                self.state['attempts'] = 0
        self.save()

    def watch(self):
        g, state = self.gateway, self.state
        if not state.get('enabled') or not state.get('pending'):
            return g.public()
        if not self.matches():
            self.disable('policy_or_runtime_changed')
            return g.public()
        now, boot = clock()
        if state.get('boot_id') != boot or now < (state.get('last_probe') or 0):
            # Samples from a previous boot can never authorize a return.
            new_window(state, now, boot, 900 if state.get('attempts', 0) > 1 else 0)
            self.save()
        if now < state['retry_after']:
            return g.public()
        if ready(state, now):
            # A separate tick leaves the full watchdog timeout for activation/rollback.
            state['pending'] = False
            self.save()
            try:
                g.rules(seconds=180, automatic=True)
                g.confirm(automatic=True)
            except Exception:
                # rules() already rolls back activation errors. A failed confirmation
                # also needs direct recovery, never an unconfirmed live rules mode.
                if g.mode_path.read_text().strip() == 'rules':
                    g.direct('auto_return_failed', automatic=True)
                self.state = state
                if self.matches():
                    self.schedule_retry()
                else:
                    self.disable('policy_or_runtime_changed')
                return g.public({'kind': 'auto_return_failed', 'reason': 'retry_after_cooldown'})
            state.update(pending=False, active_since=clock()[0], last_return_at=int(time.time()))
            self.state = state
            self.save()
            return g.public({'kind': 'automatic_return', 'reason': 'tunnel_stable'})
        last = state.get('last_probe')
        if last is None or now - last >= INTERVAL:
            ok = g.probe_uplink()
            # Measure at completion; slow probes do not accelerate the stability window.
            sample(state, ok, clock()[0])
            self.save()
        return g.public()

    def status(self):
        state = self.state
        now, boot = clock()
        pending = bool(state.get('enabled') and state.get('pending'))
        cooldown = max(0, int(state.get('retry_after', 0) - now)) if state.get('boot_id') == boot else 0
        phase = 'disabled' if not state.get('enabled') else 'armed'
        if pending:
            phase = 'cooldown' if cooldown else ('ready' if ready(state, now) and state.get('boot_id') == boot else 'checking')
        return {'enabled': bool(state.get('enabled')), 'pending': pending, 'phase': phase,
                'successful_checks': state.get('successes', 0), 'required_checks': SUCCESSES,
                'stable_seconds': STABLE_SECONDS, 'probe_interval_seconds': INTERVAL,
                'cooldown_remaining_seconds': cooldown, 'attempts': state.get('attempts', 0),
                'last_probe_ok': state.get('last_probe_ok'),
                'disabled_reason': state.get('disabled_reason'), 'last_return_at': state.get('last_return_at')}

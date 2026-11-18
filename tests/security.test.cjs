const test = require('node:test');
const assert = require('node:assert/strict');
const sec = require('../src/security.js');

// Synthetic fixtures only. No real tenant, user or IP data.
const UID = '00uSYNTHUSER0001';
const ADMIN = '00uSYNTHADMIN001';
const T0 = Date.parse('2026-11-10T12:00:00.000Z');
let n = 0;
function ev(eventType, minutes, over = {}) {
  n += 1;
  return Object.assign({
    uuid: `evt-${n}`,
    published: new Date(T0 + minutes * 60000).toISOString(),
    eventType,
    outcome: { result: 'SUCCESS' },
    actor: { id: UID, type: 'User', alternateId: 'test.user@example.com' },
    target: [{ id: UID, type: 'User' }],
    client: { ipAddress: '198.51.100.10', geographicalContext: { city: 'Springfield', country: 'United States' }, userAgent: { browser: 'CHROME', os: 'Mac OS X' } },
    transaction: { id: `tx-${n}` }
  }, over);
}
const ids = r => r.signals.map(s => s.id);

test('parses behaviors and risk from string and logOnlySecurityData forms', () => {
  const a = ev('user.session.start', 0, { debugContext: { debugData: {
    behaviors: '{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=POSITIVE, Velocity=POSITIVE}',
    risk: '{reasons=Anomalous Geo-Distance, New Device, New IP, level=HIGH}' } } });
  assert.deepEqual(sec.behaviorsOf(a), { 'New Geo-Location': 'POSITIVE', 'New Device': 'NEGATIVE', 'New IP': 'POSITIVE', 'Velocity': 'POSITIVE' });
  assert.deepEqual(sec.riskOf(a), { level: 'HIGH', reasons: 'Anomalous Geo-Distance, New Device, New IP', detection: '' });
  const b = ev('user.session.start', 0, { debugContext: { debugData: {
    logOnlySecurityData: JSON.stringify({ risk: { level: 'MEDIUM', reasons: 'New Country' }, behaviors: { 'New Country': 'POSITIVE' } }) } } });
  assert.equal(sec.behaviorsOf(b)['New Country'], 'POSITIVE');
  assert.equal(sec.riskOf(b).level, 'MEDIUM');
  assert.deepEqual(sec.behaviorsOf(ev('user.session.start', 0, { debugContext: { debugData: { logOnlySecurityData: 'not json' } } })), {});
});

test('push denials followed by success are high severity MFA fatigue', () => {
  const events = [
    ev('system.push.send_factor_verify_push', 0), ev('user.mfa.okta_verify.deny_push', 1, { outcome: { result: 'FAILURE' } }),
    ev('system.push.send_factor_verify_push', 2), ev('user.mfa.okta_verify.deny_push', 3, { outcome: { result: 'FAILURE' } }),
    ev('system.push.send_factor_verify_push', 4), ev('user.authentication.auth_via_mfa', 5, { debugContext: { debugData: { factor: 'OKTA_VERIFY_PUSH' } } })
  ];
  const r = sec.analyzeSecurity(events, { userId: UID });
  const s = r.signals.find(x => x.id === 'mfa_fatigue_accepted');
  assert.ok(s);
  assert.equal(s.severity, 'high');
  assert.match(s.observed, /2 Okta Verify push\(es\) were denied/);
  assert.match(s.observed, /3 push prompt\(s\)/);
});

test('Identity Engine failed push via auth_via_mfa counts as a denial', () => {
  const deny = ev('user.authentication.auth_via_mfa', 0, { outcome: { result: 'FAILURE' }, debugContext: { debugData: { factor: 'OKTA_VERIFY_PUSH' } } });
  assert.equal(sec.isPushDenial(deny), true);
  assert.equal(sec.isPushDenial(ev('user.authentication.auth_via_mfa', 0, { outcome: { result: 'FAILURE' }, debugContext: { debugData: { factor: 'PASSWORD' } } })), false);
});

test('three denials without success are medium; one denial or spread-out denials are not flagged', () => {
  const deny = m => ev('user.mfa.okta_verify.deny_push', m, { outcome: { result: 'FAILURE' } });
  assert.deepEqual(ids(sec.analyzeSecurity([deny(0), deny(2), deny(4)])), ['mfa_push_denials']);
  assert.deepEqual(ids(sec.analyzeSecurity([deny(0)])), []);
  assert.deepEqual(ids(sec.analyzeSecurity([deny(0), deny(30), deny(60)])), []);
  // A success long after the denials is not treated as an accepted prompt.
  assert.deepEqual(ids(sec.analyzeSecurity([deny(0), deny(1), ev('user.session.start', 45)])), []);
});

test('user-reported suspicious activity and admin privilege grants are high', () => {
  const r = sec.analyzeSecurity([
    ev('user.account.report_suspicious_activity_by_enduser', 0),
    ev('user.account.privilege.grant', 5, { actor: { id: ADMIN, alternateId: 'admin@example.com' } })
  ], { userId: UID });
  assert.deepEqual(ids(r).sort(), ['admin_privilege_granted', 'user_reported_suspicious']);
  assert.ok(r.signals.every(s => s.severity === 'high'));
  assert.match(r.signals.find(s => s.id === 'admin_privilege_granted').observed, /admin@example\.com/);
});

test('MFA factor reset by another account is reported; security-question resets are ignored', () => {
  const r = sec.analyzeSecurity([
    ev('user.mfa.factor.reset_all', 0, { actor: { id: ADMIN, alternateId: 'helpdesk@example.com' } }),
    ev('user.mfa.factor.activate', 20)
  ], { userId: UID });
  const s = r.signals.find(x => x.id === 'mfa_factor_removed');
  assert.equal(s.title, 'MFA factor removed and a new factor enrolled');
  assert.match(s.observed, /performed by another account/);
  assert.deepEqual(ids(sec.analyzeSecurity([ev('user.mfa.factor.deactivate', 0, { outcome: { result: 'SUCCESS', reason: 'User reset SECURITY_QUESTION factor' } })])), []);
});

test('risky and impossible-travel sign-ins are flagged; new device alone is low', () => {
  const high = ev('user.session.start', 0, { debugContext: { debugData: { risk: '{reasons=New Country, level=HIGH}' } } });
  const travel = ev('user.session.start', 60, { debugContext: { debugData: { behaviors: '{Velocity=POSITIVE, New Country=POSITIVE}' } } });
  const device = ev('user.session.start', 120, { debugContext: { debugData: { behaviors: '{New Device=POSITIVE, New Country=NEGATIVE}' } } });
  const r = sec.analyzeSecurity([high, travel, device]);
  const risky = r.signals.filter(s => s.id === 'risky_sign_in');
  assert.equal(risky.length, 2);
  assert.equal(risky.find(s => /HIGH/.test(s.title)).severity, 'high');
  assert.equal(risky.find(s => /impossible-travel/.test(s.title)).severity, 'medium');
  const low = r.signals.find(s => s.id === 'new_sign_in_behavior');
  assert.equal(low.severity, 'low');
  assert.match(low.observed, /1 sign-in\(s\).*New Device/);
});

test('session start and policy evaluation of one sign-in are merged', () => {
  const session = { externalSessionId: 'sess-1' };
  const r = sec.analyzeSecurity([
    ev('policy.evaluate_sign_on', 0, { authenticationContext: session, debugContext: { debugData: { risk: '{level=MEDIUM}' } } }),
    ev('user.session.start', 0.1, { authenticationContext: session, debugContext: { debugData: { behaviors: '{New IP=POSITIVE}' } } })
  ]);
  assert.equal(r.signals.length, 1);
  assert.match(r.signals[0].observed, /succeeded.*MEDIUM.*New IP/);
});

test('unusual sign-in followed by MFA reset and new factor is a possible takeover', () => {
  const r = sec.analyzeSecurity([
    ev('user.session.start', 0, { debugContext: { debugData: { behaviors: '{New Country=POSITIVE}' } }, client: { ipAddress: '203.0.113.7', geographicalContext: { country: 'Elsewhere' } } }),
    ev('user.mfa.factor.deactivate', 30),
    ev('user.mfa.factor.activate', 35)
  ], { userId: UID });
  const s = r.signals.find(x => x.id === 'possible_account_takeover');
  assert.ok(s, ids(r).join(','));
  assert.equal(s.severity, 'high');
  assert.equal(r.signals[0].severity, 'high');
  assert.deepEqual(s.evidence.map(e => e.eventType), ['user.session.start', 'user.mfa.factor.deactivate', 'user.mfa.factor.activate']);
});

test('new device sign-in followed only by enrolling a factor is NOT a takeover', () => {
  const r = sec.analyzeSecurity([
    ev('user.session.start', 0, { debugContext: { debugData: { behaviors: '{New Device=POSITIVE}' } } }),
    ev('user.mfa.factor.activate', 10)
  ], { userId: UID });
  assert.ok(!ids(r).includes('possible_account_takeover'));
});

test('account changes more than 24h after the unusual sign-in are not linked', () => {
  const r = sec.analyzeSecurity([
    ev('user.session.start', 0, { debugContext: { debugData: { risk: '{level=MEDIUM}' } } }),
    ev('user.account.reset_password', 25 * 60)
  ]);
  assert.ok(!ids(r).includes('possible_account_takeover'));
});

test('lockout reports preceding failures and escalates with many source IPs', () => {
  const fail = (m, ip) => ev('user.session.start', m, { outcome: { result: 'FAILURE', reason: 'INVALID_CREDENTIALS' }, client: { ipAddress: ip } });
  const r = sec.analyzeSecurity([fail(0, '192.0.2.1'), fail(1, '192.0.2.2'), fail(2, '192.0.2.3'), fail(3, '192.0.2.4'), ev('user.account.lock', 4)]);
  const s = r.signals.find(x => x.id === 'account_lockout');
  assert.equal(s.severity, 'high');
  assert.match(s.observed, /4 failed sign-in attempt\(s\).*4 different IP/);
  const single = sec.analyzeSecurity([fail(0, '192.0.2.1'), fail(1, '192.0.2.1'), ev('user.account.lock', 2)]);
  assert.equal(single.signals[0].severity, 'medium');
});

test('partner-reported risk via ITP is recognized and points to the partner console', () => {
  const r = sec.analyzeSecurity([
    ev('user.risk.detect', 0, { debugContext: { debugData: { risk: '{detectionName=Security Events Provider Reported Risk, level=HIGH}' } } }),
    ev('security.events.provider.receive_event', 0)
  ]);
  const partner = r.signals.find(s => s.id === 'partner_reported_risk');
  assert.equal(partner.severity, 'high');
  assert.match(partner.nextSteps.join(' '), /partner console/);
  assert.ok(ids(r).includes('partner_security_event'));
  assert.equal(r.coverage.notes.some(n => /Identity Threat Protection/.test(n)), false);
});

test('coverage notes explain missing risk data and missing ITP events', () => {
  const r = sec.analyzeSecurity([ev('user.session.start', 0)]);
  assert.equal(r.signals.length, 0);
  assert.equal(r.coverage.signIns, 1);
  assert.equal(r.coverage.signInsWithRiskData, 0);
  assert.equal(r.coverage.notes.length, 2);
});

test('signals are sorted by severity and counted; bad input is tolerated', () => {
  const r = sec.analyzeSecurity([
    ev('user.mfa.factor.deactivate', 0),
    ev('user.account.report_suspicious_activity_by_enduser', 5),
    { eventType: 'user.account.lock' }, null, 'junk'
  ]);
  assert.deepEqual(r.signals.map(s => s.severity), ['high', 'medium']);
  assert.deepEqual(r.counts, { high: 1, medium: 1, low: 0 });
  assert.deepEqual(sec.analyzeSecurity(null).signals, []);
});

test('takeover evidence is not duplicated and the sequence is listed first', () => {
  const session = ev('user.session.start', 5, { debugContext: { debugData: { behaviors: '{New Country=POSITIVE}' } } });
  const r = sec.analyzeSecurity([
    ev('user.mfa.okta_verify.deny_push', 0, { outcome: { result: 'FAILURE' } }),
    ev('user.mfa.okta_verify.deny_push', 1, { outcome: { result: 'FAILURE' } }),
    session,
    ev('user.account.privilege.grant', 60, { actor: { id: ADMIN, alternateId: 'admin@example.com' } })
  ], { userId: UID });
  assert.equal(r.signals[0].id, 'possible_account_takeover');
  const evidenceIds = r.signals[0].evidence.map(e => e.eventId);
  assert.equal(new Set(evidenceIds).size, evidenceIds.length);
});

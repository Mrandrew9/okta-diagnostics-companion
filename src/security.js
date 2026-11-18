/*
 * Identity security signals for Okta Diagnostics Companion.
 * Pure functions: no network requests or browser APIs. Testable with Node.js.
 *
 * Every signal is derived only from System Log events that were actually
 * returned for the selected user and time window. A signal is a lead for an
 * investigator, not a verdict; the absence of signals does not prove an
 * account is safe.
 */
(function (root) {
  'use strict';

  const SEVERITY = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low' });
  const SEVERITY_RANK = Object.freeze({ high: 3, medium: 2, low: 1 });

  const MINUTE = 60 * 1000;
  const PUSH_WINDOW_MS = 10 * MINUTE;      // Sequence window used by common MFA-fatigue rules.
  const LOCKOUT_LOOKBACK_MS = 60 * MINUTE;
  const TAKEOVER_WINDOW_MS = 24 * 60 * MINUTE;
  const MAX_EVIDENCE = 8;

  const EVENT = Object.freeze({
    PUSH_SENT: 'system.push.send_factor_verify_push',
    PUSH_DENY: 'user.mfa.okta_verify.deny_push',
    AUTH_VIA_MFA: 'user.authentication.auth_via_mfa',
    SESSION_START: 'user.session.start',
    SSO: 'user.authentication.sso',
    VERIFY: 'user.authentication.verify',
    POLICY_SIGN_ON: 'policy.evaluate_sign_on',
    REPORTED_SUSPICIOUS: 'user.account.report_suspicious_activity_by_enduser',
    FACTOR_ACTIVATE: 'user.mfa.factor.activate',
    FACTOR_DEACTIVATE: 'user.mfa.factor.deactivate',
    FACTOR_RESET_ALL: 'user.mfa.factor.reset_all',
    FACTOR_SUSPEND: 'user.mfa.factor.suspend',
    PRIVILEGE_GRANT: 'user.account.privilege.grant',
    IMPERSONATION_GRANT: 'user.session.impersonation.grant',
    IMPERSONATION_INITIATE: 'user.session.impersonation.initiate',
    RISK_DETECT: 'user.risk.detect',
    PROVIDER_EVENT: 'security.events.provider.receive_event',
    THREAT_DETECTED: 'security.threat.detected',
    ACCOUNT_LOCK: 'user.account.lock',
    PASSWORD_RESET: 'user.account.reset_password'
  });

  const FACTOR_REMOVALS = new Set([EVENT.FACTOR_DEACTIVATE, EVENT.FACTOR_RESET_ALL, EVENT.FACTOR_SUSPEND]);
  const SUCCESSFUL_AUTH = new Set([EVENT.AUTH_VIA_MFA, EVENT.SESSION_START, EVENT.SSO, EVENT.VERIFY]);
  const FAILED_SIGN_IN = new Set([EVENT.SESSION_START, EVENT.VERIFY, EVENT.AUTH_VIA_MFA]);
  // Changes that help an attacker keep access. A new factor enrolment on its own
  // is routine (new phone/laptop), so it only counts alongside a factor removal.
  const ACCOUNT_CHANGES = new Set([
    EVENT.FACTOR_DEACTIVATE, EVENT.FACTOR_RESET_ALL, EVENT.FACTOR_SUSPEND,
    EVENT.PRIVILEGE_GRANT, EVENT.PASSWORD_RESET, EVENT.IMPERSONATION_GRANT
  ]);
  // Location changes strong enough to start a takeover sequence on their own.
  const LOCATION_BEHAVIORS = ['New Country', 'New Geo-Location', 'Velocity'];
  // Behaviors that indicate a meaningful change in where/how the user signed in.
  const NOTABLE_BEHAVIORS = ['New Country', 'New Geo-Location', 'New State', 'New City', 'New Device', 'New IP', 'New ASN', 'Velocity'];

  // ---- small helpers -------------------------------------------------------

  function result(event) { return String(event?.outcome?.result || '').toUpperCase(); }
  function time(event) { const t = Date.parse(event?.published || ''); return Number.isFinite(t) ? t : NaN; }
  function debugData(event) { const d = event?.debugContext?.debugData; return d && typeof d === 'object' ? d : {}; }
  function byTime(a, b) { return time(a) - time(b); }

  function isSelf(event, userId) {
    return Boolean(userId) && String(event?.actor?.id || '') === String(userId);
  }

  function location(event) {
    const g = event?.client?.geographicalContext || {};
    return [g.city, g.state, g.country].filter(Boolean).join(', ');
  }

  function clientLabel(event) {
    const ua = event?.client?.userAgent || {};
    return [ua.browser, ua.os].filter(v => v && v !== 'UNKNOWN').join(' on ');
  }

  function evidence(event) {
    return {
      published: event?.published || '',
      eventType: event?.eventType || '',
      outcome: event?.outcome?.result || '',
      reason: event?.outcome?.reason || '',
      actor: event?.actor?.alternateId || event?.actor?.displayName || '',
      ip: event?.client?.ipAddress || '',
      location: location(event),
      client: clientLabel(event),
      message: event?.displayMessage || '',
      eventId: event?.uuid || ''
    };
  }

  function makeSignal(id, severity, title, observed, why, nextSteps, events) {
    const sorted = [...events].sort(byTime);
    return {
      id, severity, title, observed, why, nextSteps,
      first: sorted[0]?.published || '',
      last: sorted[sorted.length - 1]?.published || '',
      eventCount: sorted.length,
      evidence: sorted.slice(-MAX_EVIDENCE).map(evidence)
    };
  }

  // ---- Okta risk / behavior parsing --------------------------------------

  // Okta records behaviors either as a string such as
  // "{New Geo-Location=POSITIVE, New Device=NEGATIVE}" or inside the JSON
  // string debugData.logOnlySecurityData. Both are accepted.
  function parseLogOnlySecurityData(event) {
    const raw = debugData(event).logOnlySecurityData;
    if (!raw) return null;
    if (typeof raw === 'object') return raw;
    try { return JSON.parse(String(raw)); } catch { return null; }
  }

  function behaviorsOf(event) {
    const out = {};
    const add = (name, value) => {
      const key = String(name || '').trim();
      const val = String(value || '').trim().toUpperCase();
      if (key && val) out[key] = val;
    };
    const raw = debugData(event).behaviors;
    if (raw && typeof raw === 'object') Object.entries(raw).forEach(([k, v]) => add(k, v));
    else if (raw) {
      for (const m of String(raw).matchAll(/([A-Za-z][A-Za-z -]*?)\s*=\s*(POSITIVE|NEGATIVE|UNKNOWN|BAD_REQUEST)/gi)) add(m[1], m[2]);
    }
    const logOnly = parseLogOnlySecurityData(event);
    if (logOnly?.behaviors && typeof logOnly.behaviors === 'object') {
      Object.entries(logOnly.behaviors).forEach(([k, v]) => { if (!(String(k).trim() in out)) add(k, v); });
    }
    return out;
  }

  function riskOf(event) {
    let level = '';
    let reasons = '';
    let detection = '';
    const raw = debugData(event).risk;
    if (raw && typeof raw === 'object') {
      level = raw.level || '';
      reasons = Array.isArray(raw.reasons) ? raw.reasons.join(', ') : (raw.reasons || '');
      detection = raw.detectionName || '';
    } else if (raw) {
      const text = String(raw);
      level = (text.match(/\blevel\s*=\s*([A-Z]+)/i) || [])[1] || '';
      reasons = (text.match(/\breasons\s*=\s*(.*?)(?:,\s*(?:level|detectionName|issuer)\s*=|\}\s*$|$)/i) || [])[1] || '';
      detection = (text.match(/\bdetectionName\s*=\s*([^,}]+)/i) || [])[1] || '';
    }
    const logOnly = parseLogOnlySecurityData(event);
    if (!level && logOnly?.risk) {
      level = logOnly.risk.level || '';
      if (!reasons) reasons = Array.isArray(logOnly.risk.reasons) ? logOnly.risk.reasons.join(', ') : (logOnly.risk.reasons || '');
    }
    return { level: String(level).toUpperCase(), reasons: String(reasons).trim(), detection: String(detection).trim() };
  }

  function severityForRisk(level) {
    if (level === 'HIGH') return SEVERITY.HIGH;
    if (level === 'MEDIUM') return SEVERITY.MEDIUM;
    return SEVERITY.LOW;
  }

  // ---- detections -------------------------------------------------------

  function isPushDenial(event) {
    if (event?.eventType === EVENT.PUSH_DENY) return true;
    // Identity Engine records a rejected push as a failed auth_via_mfa with factor OKTA_VERIFY_PUSH.
    return event?.eventType === EVENT.AUTH_VIA_MFA && result(event) === 'FAILURE' &&
      String(debugData(event).factor || '').toUpperCase() === 'OKTA_VERIFY_PUSH';
  }

  function chains(events, gapMs) {
    const out = [];
    for (const e of events) {
      const last = out[out.length - 1];
      if (last && time(e) - time(last[last.length - 1]) <= gapMs) last.push(e);
      else out.push([e]);
    }
    return out;
  }

  function detectPushFatigue(events) {
    const signals = [];
    const denials = events.filter(isPushDenial).sort(byTime);
    const pushes = events.filter(e => e.eventType === EVENT.PUSH_SENT);
    const successes = events.filter(e => SUCCESSFUL_AUTH.has(e.eventType) && result(e) === 'SUCCESS');
    for (const chain of chains(denials, PUSH_WINDOW_MS)) {
      const start = time(chain[0]);
      const end = time(chain[chain.length - 1]);
      const accepted = successes.filter(s => time(s) > end && time(s) - end <= PUSH_WINDOW_MS).sort(byTime)[0];
      const until = accepted ? time(accepted) : end;
      const relatedPushes = pushes.filter(p => time(p) >= start - PUSH_WINDOW_MS && time(p) <= until);
      const pushCount = relatedPushes.length;
      const pushNote = pushCount ? ` ${pushCount} push prompt(s) were sent in the same period.` : '';
      if (chain.length >= 2 && accepted) {
        signals.push(makeSignal('mfa_fatigue_accepted', SEVERITY.HIGH,
          'Denied MFA pushes followed by a successful sign-in',
          `${chain.length} Okta Verify push(es) were denied within ${Math.round((end - start) / MINUTE) || 1} minute(s), then authentication succeeded at ${accepted.published}.${pushNote}`,
          'Repeated push prompts that the user rejects, followed by an approval, is the pattern of an MFA fatigue (push bombing) attack: an attacker with the password keeps sending prompts until the user accepts one.',
          ['Contact the user through a trusted channel (not the account under investigation) and ask whether they initiated these sign-ins.',
            'Compare IP address, location and client of the denied prompts with the successful sign-in below.',
            'If the user did not sign in, follow your incident response procedure (for example clearing sessions, resetting the password and re-enrolling factors) with approval.',
            'Consider phishing-resistant authenticators or number matching for this user\'s policy.'],
          [...chain, ...relatedPushes, accepted]));
      } else if (chain.length >= 3) {
        signals.push(makeSignal('mfa_push_denials', SEVERITY.MEDIUM,
          'Repeated MFA push denials',
          `${chain.length} Okta Verify push(es) were denied within ${Math.round((end - start) / MINUTE) || 1} minute(s); no successful sign-in followed within 10 minutes.${pushNote}`,
          'Several rejected prompts in a short period suggest someone else has the user\'s password and is trying to get past MFA.',
          ['Confirm with the user through a trusted channel whether they triggered these prompts.',
            'Review the IP addresses and locations below for sign-in attempts the user does not recognize.',
            'If the attempts are not the user\'s, treat the password as compromised and follow your approved procedure.'],
          chain));
      }
    }
    return signals;
  }

  function detectUserReported(events) {
    const reported = events.filter(e => e.eventType === EVENT.REPORTED_SUSPICIOUS);
    if (!reported.length) return [];
    return [makeSignal('user_reported_suspicious', SEVERITY.HIGH,
      'User reported suspicious activity',
      `The user reported suspicious activity ${reported.length} time(s) in response to an Okta security notification.`,
      'The user told Okta they did not recognize activity on their account. This is direct evidence that should be investigated.',
      ['Review the sign-ins and account changes immediately before each report.',
        'Contact the user through a trusted channel to understand what they saw.',
        'Follow your incident response procedure if the activity is confirmed as unauthorized.'],
      reported)];
  }

  function detectFactorChanges(events, userId) {
    const removals = events.filter(e => FACTOR_REMOVALS.has(e.eventType) && result(e) === 'SUCCESS' &&
      !/SECURITY_QUESTION/i.test(String(e?.outcome?.reason || '')));
    if (!removals.length) return [];
    const activations = events.filter(e => e.eventType === EVENT.FACTOR_ACTIVATE && result(e) === 'SUCCESS');
    const lastRemoval = Math.max(...removals.map(time));
    const followUp = activations.filter(a => time(a) > Math.min(...removals.map(time)) && time(a) - lastRemoval <= TAKEOVER_WINDOW_MS);
    const byOthers = removals.filter(e => userId && !isSelf(e, userId));
    const who = byOthers.length ? `${byOthers.length} performed by another account (for example an admin or helpdesk)` : 'performed by the user';
    return [makeSignal('mfa_factor_removed', SEVERITY.MEDIUM,
      followUp.length ? 'MFA factor removed and a new factor enrolled' : 'MFA factor removed or reset',
      `${removals.length} factor removal/reset event(s), ${who}.${followUp.length ? ` ${followUp.length} new factor enrolment(s) followed within 24 hours.` : ''}`,
      'Removing or resetting MFA weakens the account. Attackers who reach a helpdesk or an admin account often reset a victim\'s factors and enrol their own device. Legitimate device replacements look similar, so confirm intent.',
      ['Confirm the reset was requested by the user and verified through your helpdesk identity-verification process.',
        'Check where the new factor was enrolled from (IP, location, client) and whether it matches the user.',
        'If the change was not expected, follow your approved procedure to remove the unrecognized factor and secure the account.'],
      [...removals, ...followUp])];
  }

  function detectPrivilegeGrant(events) {
    const grants = events.filter(e => e.eventType === EVENT.PRIVILEGE_GRANT && result(e) !== 'FAILURE');
    if (!grants.length) return [];
    return [makeSignal('admin_privilege_granted', SEVERITY.HIGH,
      'Admin privileges granted',
      `Okta admin privileges were granted ${grants.length} time(s). Granted by: ${[...new Set(grants.map(g => g?.actor?.alternateId || 'unknown'))].join(', ')}.`,
      'New admin rights expand what this account can change in Okta. Unexpected grants are a common step after an account takeover, to keep access or move further.',
      ['Confirm the grant matches an approved access request or change ticket.',
        'Verify the account that granted the role was itself used legitimately at that time.',
        'If not approved, escalate through your incident response procedure before revoking, so evidence is preserved.'],
      grants)];
  }

  function detectImpersonation(events) {
    const imp = events.filter(e => (e.eventType === EVENT.IMPERSONATION_GRANT || e.eventType === EVENT.IMPERSONATION_INITIATE) && result(e) !== 'FAILURE');
    if (!imp.length) return [];
    return [makeSignal('support_impersonation', SEVERITY.MEDIUM,
      'Support impersonation access granted or used',
      `${imp.length} support impersonation event(s) were recorded.`,
      'Impersonation lets another party act inside the org. It should match a known support case.',
      ['Match each event to an open support case.', 'If there is no matching case, review the actions taken during the impersonation session and escalate.'],
      imp)];
  }

  function signInKey(event) {
    return event?.authenticationContext?.externalSessionId || event?.transaction?.id || event?.uuid || event?.published;
  }

  function detectSignInAnomalies(events, anchors) {
    const signals = [];
    const groups = new Map();
    for (const e of events) {
      if (e.eventType !== EVENT.SESSION_START && e.eventType !== EVENT.POLICY_SIGN_ON) continue;
      const k = signInKey(e);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(e);
    }
    const low = [];
    for (const group of groups.values()) {
      const behaviors = {};
      let risk = { level: '', reasons: '', detection: '' };
      for (const e of group) {
        Object.assign(behaviors, behaviorsOf(e));
        const r = riskOf(e);
        if ((SEVERITY_RANK[severityForRisk(r.level)] || 0) > (SEVERITY_RANK[severityForRisk(risk.level)] || 0) || (!risk.level && r.level)) risk = r;
      }
      const positive = NOTABLE_BEHAVIORS.filter(b => behaviors[b] === 'POSITIVE');
      const succeeded = group.some(e => e.eventType === EVENT.SESSION_START && result(e) === 'SUCCESS');
      const outcome = succeeded ? 'The sign-in succeeded.' : 'No successful session start was recorded for this sign-in.';
      const behaviorText = positive.length ? ` New behavior detected by Okta: ${positive.join(', ')}.` : '';
      const riskText = risk.level ? ` Okta risk level: ${risk.level}${risk.reasons ? ` (${risk.reasons})` : ''}.` : '';
      if (risk.level === 'HIGH' || risk.level === 'MEDIUM' || positive.some(b => LOCATION_BEHAVIORS.includes(b))) {
        anchors.push(...group);
      }
      if (risk.level === 'HIGH' || risk.level === 'MEDIUM' || positive.includes('Velocity')) {
        const severity = risk.level === 'HIGH' ? SEVERITY.HIGH : SEVERITY.MEDIUM;
        signals.push(makeSignal('risky_sign_in', severity,
          positive.includes('Velocity') && risk.level !== 'HIGH' ? 'Sign-in with impossible-travel behavior' : `Sign-in rated ${risk.level || 'MEDIUM'} risk by Okta`,
          `${outcome}${riskText}${behaviorText}`,
          'Okta\'s risk scoring and behavior detection judged this sign-in unusual for the user (for example a new country, a new device, or travel too fast to be physically possible).',
          ['Ask the user, through a trusted channel, whether they signed in from this location and device.',
            'Review account changes that followed this sign-in (MFA, password, admin rights).',
            'If not recognized, follow your incident response procedure.'],
          group));
      } else if (positive.length) {
        low.push({ group, positive });
      }
    }
    if (low.length) {
      const names = [...new Set(low.flatMap(l => l.positive))];
      signals.push(makeSignal('new_sign_in_behavior', SEVERITY.LOW,
        'Sign-ins with new location, device or network',
        `${low.length} sign-in(s) where Okta detected: ${names.join(', ')}.`,
        'New behavior is often legitimate (travel, a new laptop). It matters most when combined with other signals in this list.',
        ['Check whether the locations and devices below are expected for this user.'],
        low.flatMap(l => l.group)));
    }
    return signals;
  }

  function detectThreatProtection(events) {
    const signals = [];
    for (const e of events.filter(ev => ev.eventType === EVENT.RISK_DETECT)) {
      const risk = riskOf(e);
      const partner = /Security Events Provider/i.test(risk.detection + ' ' + JSON.stringify(debugData(e).risk || ''));
      signals.push(makeSignal(partner ? 'partner_reported_risk' : 'itp_risk_detected', severityForRisk(risk.level),
        partner ? 'Security partner reported risk (for example EDR)' : 'Identity Threat Protection risk detection',
        `Okta recorded an entity risk detection${risk.level ? ` at level ${risk.level}` : ''}${risk.detection ? `: ${risk.detection}` : ''}${risk.reasons ? ` (${risk.reasons})` : ''}.`,
        partner
          ? 'A connected security tool (such as CrowdStrike Falcon) sent a risk signal about this user to Okta. Okta records the event, but the original context is in the partner tool.'
          : 'Okta Identity Threat Protection raised this user\'s risk based on observed activity.',
        partner
          ? ['Open the partner console (for example the EDR) and review the detection for this user or device at this time.', 'Check whether Okta\'s entity risk policy took an action (for example logout) and whether the risk has since been lowered.']
          : ['Review the user\'s risk details in the Admin Console and the activity around this time.', 'Follow your entity risk policy and incident procedure.'],
        [e]));
    }
    const received = events.filter(ev => ev.eventType === EVENT.PROVIDER_EVENT);
    if (received.length) {
      signals.push(makeSignal('partner_security_event', SEVERITY.MEDIUM,
        'Security events received from a partner provider',
        `${received.length} Shared Signals (SSF/CAEP) event(s) from a connected security provider were recorded.`,
        'A connected security tool sent Okta information about this user\'s session, credentials or device.',
        ['Open the event details below and the partner console to see what the provider reported.'],
        received));
    }
    return signals;
  }

  function detectLockouts(events) {
    const locks = events.filter(e => e.eventType === EVENT.ACCOUNT_LOCK);
    if (!locks.length) return [];
    const failures = events.filter(e => FAILED_SIGN_IN.has(e.eventType) && result(e) === 'FAILURE' &&
      locks.some(l => time(e) <= time(l) && time(l) - time(e) <= LOCKOUT_LOOKBACK_MS));
    const ips = [...new Set(failures.map(f => f?.client?.ipAddress).filter(Boolean))];
    const ipText = ips.length > 1 ? ` The failures came from ${ips.length} different IP addresses.` : '';
    return [makeSignal('account_lockout', ips.length > 2 ? SEVERITY.HIGH : SEVERITY.MEDIUM,
      'Account locked after failed sign-ins',
      `The account was locked ${locks.length} time(s); ${failures.length} failed sign-in attempt(s) occurred in the hour before.${ipText}`,
      'Lockouts after repeated failures can be a forgotten password, but failures from several IP addresses suggest password guessing, spraying or credential stuffing.',
      ['Check whether the IP addresses and locations below belong to the user.',
        'Confirm with the user before unlocking if the attempts look unfamiliar.',
        'If attempts are malicious, follow your approved procedure (for example password reset and blocking the source network zone).'],
      [...failures, ...locks])];
  }

  function detectThreatInsight(events) {
    const threats = events.filter(e => e.eventType === EVENT.THREAT_DETECTED);
    if (!threats.length) return [];
    return [makeSignal('threat_detected', SEVERITY.MEDIUM,
      'Okta detected a security threat',
      `${threats.length} security.threat.detected event(s) were recorded for this user.`,
      'Okta flagged requests involving this user as a threat (for example from a known-malicious IP or suspicious request pattern).',
      ['Review the source IP addresses and the reason recorded on each event.', 'Check whether any related sign-in succeeded.'],
      threats)];
  }

  // A suspicious sign-in (or accepted push-fatigue sequence) followed by an
  // account change within 24 hours is the typical shape of an account takeover.
  function detectTakeoverSequence(events, signals, signInAnchors) {
    const fatigueAnchors = signals.filter(s => s.id === 'mfa_fatigue_accepted')
      .map(s => s.evidence[s.evidence.length - 1]).filter(Boolean)
      .map(ev => events.find(e => (ev.eventId && e.uuid === ev.eventId) || e.published === ev.published)).filter(Boolean);
    const anchorEventsAll = [...new Map([...signInAnchors, ...fatigueAnchors].map(e => [e.uuid || `${e.published}|${e.eventType}`, e])).values()];
    if (!anchorEventsAll.length) return [];
    const anchorTimes = [...new Set(anchorEventsAll.map(time))].sort((a, b) => a - b);
    const within = e => anchorTimes.some(t => time(e) > t && time(e) - t <= TAKEOVER_WINDOW_MS);
    let changes = events.filter(e => ACCOUNT_CHANGES.has(e.eventType) && result(e) === 'SUCCESS' && within(e));
    if (!changes.length) return [];
    if (changes.some(e => FACTOR_REMOVALS.has(e.eventType))) {
      changes = [...changes, ...events.filter(e => e.eventType === EVENT.FACTOR_ACTIVATE && result(e) === 'SUCCESS' && within(e))];
    }
    const firstChange = Math.min(...changes.map(time));
    const anchor = anchorTimes.filter(t => t < firstChange).at(-1);
    const anchorEvents = anchorEventsAll.filter(e => time(e) === anchor);
    const kinds = [...new Set(changes.map(c => c.eventType))].join(', ');
    return [makeSignal('possible_account_takeover', SEVERITY.HIGH,
      'Possible account takeover sequence',
      `An unusual sign-in was followed within 24 hours by account changes: ${kinds}.`,
      'Attackers who get in usually change the account to keep access: enrolling their own MFA factor, resetting the password, or adding privileges. This sequence links those steps together.',
      ['Treat this as a priority investigation and confirm every step with the user through a trusted channel.',
        'Review the full event table for the period between the sign-in and the changes.',
        'If confirmed, follow your incident response procedure, preserving evidence before remediating.'],
      [...anchorEvents, ...changes])];
  }

  function coverage(events) {
    const signIns = events.filter(e => e.eventType === EVENT.SESSION_START || e.eventType === EVENT.POLICY_SIGN_ON);
    const withBehavior = signIns.filter(e => Object.keys(behaviorsOf(e)).length || riskOf(e).level);
    const notes = [];
    if (signIns.length && !withBehavior.length) {
      notes.push('Sign-in events contain no behavior or risk data, so new-location/device and risky sign-in checks could not run. Okta records this only when sign-on policies evaluate risk or behavior.');
    }
    if (!events.some(e => e.eventType === EVENT.RISK_DETECT || e.eventType === EVENT.PROVIDER_EVENT)) {
      notes.push('No Identity Threat Protection risk events were found. If your org does not use ITP, partner signals (for example CrowdStrike) cannot appear here.');
    }
    return { signIns: signIns.length, signInsWithRiskData: withBehavior.length, notes };
  }

  function analyzeSecurity(events, options) {
    const userId = options?.userId || '';
    const list = (Array.isArray(events) ? events : []).filter(e => e && typeof e === 'object' && Number.isFinite(time(e))).sort(byTime);
    const signInAnchors = [];
    const signals = [
      ...detectUserReported(list),
      ...detectPushFatigue(list),
      ...detectSignInAnomalies(list, signInAnchors),
      ...detectThreatProtection(list),
      ...detectFactorChanges(list, userId),
      ...detectPrivilegeGrant(list),
      ...detectImpersonation(list),
      ...detectLockouts(list),
      ...detectThreatInsight(list)
    ];
    signals.push(...detectTakeoverSequence(list, signals, signInAnchors));
    // Within a severity, the takeover sequence comes first because it links the other signals.
    const linked = s => (s.id === 'possible_account_takeover' ? 1 : 0);
    signals.sort((a, b) => (SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]) || (linked(b) - linked(a)) || String(b.last).localeCompare(String(a.last)));
    const counts = { high: 0, medium: 0, low: 0 };
    signals.forEach(s => { counts[s.severity] += 1; });
    return { signals, counts, coverage: coverage(list) };
  }

  const api = { SEVERITY, EVENT, behaviorsOf, riskOf, isPushDenial, analyzeSecurity };
  root.OktaSecuritySignals = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

/*
 * Pure helpers for Okta Diagnostics Companion.
 * No network requests or browser APIs. Testable with Node.js.
 */
(function (root) {
  'use strict';

  const CATEGORIES = Object.freeze({
    SIGN_IN: 'Sign-in',
    PROVISIONING: 'Provisioning',
    SECURITY: 'Security',
    OTHER: 'Other'
  });

  function validateIdentifier(value, label = 'Identifier') {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{6,128}$/.test(value)) {
      throw new Error(`${label} must be an Okta ID containing letters, numbers, underscores or hyphens.`);
    }
    return value;
  }

  function validateWindow(since, until) {
    const start = new Date(since);
    const end = new Date(until);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start >= end) {
      throw new Error('Choose a valid time window with an end after the start.');
    }
    if (end.getTime() - start.getTime() > 31 * 24 * 60 * 60 * 1000) {
      throw new Error('For safety, a report can cover at most 31 days.');
    }
    if (end.getTime() > Date.now() + 60 * 1000) {
      throw new Error('The end time cannot be in the future.');
    }
    return { since: start.toISOString(), until: end.toISOString() };
  }

  function buildUserLogUrl(origin, userId, since, until, field = 'actor.id') {
    validateIdentifier(userId, 'User ID');
    if (!['actor.id', 'target.id'].includes(field)) throw new Error('Unsupported System Log filter field.');
    const window = validateWindow(since, until);
    const url = new URL('/api/v1/logs', origin);
    url.searchParams.set('since', window.since);
    url.searchParams.set('until', window.until);
    url.searchParams.set('sortOrder', 'DESCENDING');
    url.searchParams.set('limit', '100');
    url.searchParams.set('filter', `${field} eq "${userId}"`);
    return url.href;
  }

  function parseNextLink(linkHeader, origin) {
    if (typeof linkHeader !== 'string') return null;
    const next = linkHeader.split(',').map(s => s.trim()).find(s => /;\s*rel="?next"?(?:\s*;|$)/i.test(s));
    if (!next) return null;
    const match = next.match(/^<([^>]+)>/);
    if (!match) throw new Error('Malformed Okta pagination link.');
    const url = new URL(match[1], origin);
    // Follow only the exact Okta org origin and System Log endpoint.
    if (url.origin !== new URL(origin).origin || url.pathname !== '/api/v1/logs' || url.protocol !== 'https:') {
      throw new Error('Rejected an unexpected pagination destination.');
    }
    return url.href;
  }

  async function collectLogs({ origin, userId, since, until, requestPage, pagesPerFilter = 3 }) {
    if (typeof requestPage !== 'function') throw new Error('requestPage callback is required.');
    if (!Number.isInteger(pagesPerFilter) || pagesPerFilter < 1 || pagesPerFilter > 10) {
      throw new Error('Invalid maximum page count.');
    }
    const seen = new Map();
    let pageLimitHit = false;
    for (const field of ['actor.id', 'target.id']) {
      let next = buildUserLogUrl(origin, userId, since, until, field);
      let pages = 0;
      const visited = new Set();
      while (next && pages < pagesPerFilter) {
        if (visited.has(next)) throw new Error('Okta pagination returned a repeated page link.');
        visited.add(next);
        const { events, link } = await requestPage(next);
        if (!Array.isArray(events)) throw new Error('Unexpected System Log response.');
        for (const event of events) {
          if (!event || typeof event !== 'object') continue;
          // Okta System Log events use UUID. Fallback is deterministic within this report.
          const key = event.uuid || JSON.stringify([event.published, event.eventType, event.actor?.id, event.displayMessage, event.transaction?.id]);
          if (!seen.has(key)) seen.set(key, event);
        }
        pages++;
        next = parseNextLink(link, origin);
      }
      if (next) pageLimitHit = true;
    }
    const events = [...seen.values()].sort((a, b) => (b.published || '').localeCompare(a.published || ''));
    return { events, pageLimitHit };
  }

  function classify(event) {
    const type = String(event?.eventType || '');
    if (/^(application\.provision\.|application\.user_membership\.|application\.integration\.|app\.user_management\.|app\.app_instance\.provision_)/.test(type)) {
      return CATEGORIES.PROVISIONING;
    }
    if (/^(user\.authentication\.|user\.session\.|user\.mfa\.|app\.inbound_del_auth\.)/.test(type)) {
      return CATEGORIES.SIGN_IN;
    }
    if (/^(policy\.|security\.|user\.risk\.|user\.account\.lock|application\.policy\.sign_on\.)/.test(type)) {
      return CATEGORIES.SECURITY;
    }
    return CATEGORIES.OTHER;
  }

  function outcomeResult(event) {
    return String(event?.outcome?.result || '').toUpperCase();
  }

  function isFailure(event) {
    return outcomeResult(event) === 'FAILURE';
  }

  function isDenied(event) {
    return outcomeResult(event) === 'DENY';
  }

  // Okta records policy denials as DENY rather than FAILURE; both are adverse outcomes.
  function isAdverse(event) {
    return isFailure(event) || isDenied(event);
  }

  function appTarget(event) {
    const target = Array.isArray(event?.target) ? event.target : [];
    return target.find(x => /app/i.test(String(x.type || ''))) || null;
  }

  function matchesApp(event, appId) {
    if (!appId) return true;
    return Array.isArray(event?.target) && event.target.some(t => t && t.id === appId);
  }

  function summarize(events) {
    return {
      total: events.length,
      failures: events.filter(isFailure).length,
      denials: events.filter(isDenied).length,
      signIn: events.filter(e => classify(e) === CATEGORIES.SIGN_IN).length,
      provisioning: events.filter(e => classify(e) === CATEGORIES.PROVISIONING).length,
      security: events.filter(e => classify(e) === CATEGORIES.SECURITY).length
    };
  }

  function triageHints(events) {
    const matches = [
      ['application.integration.authentication_failure', 'Downstream application API authentication failed. Check approved integration credentials and their permissions.'],
      ['application.integration.rate_limit_exceeded', 'Downstream API rate limiting was recorded. Review integration throttling and retry behavior.'],
      ['application.policy.sign_on.deny_access', 'An application sign-on policy denied access. Review the policy decision and its event evidence.'],
      ['app.app_instance.provision_sync_job.failed', 'An application provisioning synchronization job failed. Inspect that job and affected app.'],
      ['application.provision.user.push', 'A user provisioning push was attempted. Check the event outcome and any linked integration errors.']
    ];
    const hints = [];
    for (const [eventType, guidance] of matches) {
      const observed = events.filter(e => e?.eventType === eventType && isAdverse(e));
      if (observed.length) hints.push({ eventType, count: observed.length, guidance });
    }
    return hints;
  }

  /*
   * Provisioning diagnosis.
   * Causes are inferred only from error text Okta actually recorded on the event.
   * Order matters: the first matching rule wins.
   */
  const PROVISIONING_CAUSES = Object.freeze([
    {
      id: 'rate_limited',
      title: 'Downstream application rate-limited Okta',
      pattern: /\b429\b|rate[ -]?limit|too many requests|throttl/i,
      why: 'The target application rejected the request because too many calls were made in a short period.',
      checks: ['Check the application\'s API rate limits and current usage.', 'Retry the failed task in Okta after the limit window resets.', 'Avoid bulk reassignments or imports while the limit is active.']
    },
    {
      id: 'account_conflict',
      title: 'Account already exists or conflicts in the application',
      pattern: /\b409\b|already exists|duplicate|conflict|uniqueness|not unique/i,
      why: 'The application already has an account with the same unique value (often username or email), so it refused to create another.',
      checks: ['Search the application for an existing account with the same username/email.', 'Decide whether to link (match) the existing account or rename one of them.', 'Review the app username format in the Okta app\'s Sign On settings.']
    },
    {
      id: 'downstream_auth',
      title: 'Application rejected Okta\'s integration credentials',
      pattern: /\b40[13]\b|unauthori[sz]ed|forbidden|invalid (api )?(token|credential|key|client)|authentication (failed|failure|error)|access denied|insufficient (privilege|permission|scope)|(token|credential|secret)s? (has |have )?expired/i,
      why: 'The application refused the API call Okta made on the user\'s behalf. The integration token or service account is invalid, expired or lacks permission.',
      checks: ['Open the Okta app\'s Provisioning > Integration tab and test the API credentials.', 'Confirm the service account or token in the application is active and has user-management permission.', 'Re-authenticate the integration if the token was rotated or expired.']
    },
    {
      id: 'not_found_downstream',
      title: 'User or resource not found in the application',
      pattern: /\b404\b|not found|does not exist|no such (user|resource|account)/i,
      why: 'Okta tried to update or deactivate an account the application no longer has, or the integration endpoint URL is wrong.',
      checks: ['Check whether the account was deleted directly in the application.', 'Verify the base URL/endpoint configured in the Okta app\'s Provisioning settings.', 'If the account is gone, unassign and reassign the user to recreate it.']
    },
    {
      id: 'license_or_quota',
      title: 'Application license or quota exhausted',
      pattern: /licen[cs]e|\bseats?\b|quota|subscription (limit|expired)/i,
      why: 'The application refused to create or activate the account because no licenses or seats were available.',
      checks: ['Check available licenses/seats in the application\'s admin console.', 'Free or purchase a license, then retry the failed task in Okta.']
    },
    {
      id: 'response_format',
      title: 'Okta could not read the application\'s response',
      pattern: /unable to (parse|read)|unexpected (response|content|token)|content[- ]type|accept header|scim\+json|deserializ|malformed (response|json)/i,
      why: 'The application answered in a format Okta did not expect. For SCIM apps this is often a missing application/scim+json content type or a non-standard response body.',
      checks: ['Confirm the SCIM server accepts and returns application/scim+json.', 'Compare the server\'s response with the SCIM 2.0 schema Okta expects.', 'Check the application server logs for the matching request.']
    },
    {
      id: 'attribute_mapping',
      title: 'Attribute or profile value rejected',
      pattern: /\b400\b|\b422\b|bad request|required (attribute|field|property)|missing (required )?(attribute|field|property|value)|invalid (value|attribute|format|email|username|phone)|schema|mapping|validation|unprocessable|too long|must not be (null|empty|blank)/i,
      why: 'The application rejected one or more user attributes Okta sent: a required value is missing, or a value has the wrong format.',
      checks: ['Find the attribute named in the error and check the user\'s Okta profile value.', 'Review Profile Editor > Mappings (Okta to the app) for that attribute.', 'Fix the value or mapping, then retry the failed task.']
    },
    {
      id: 'downstream_unavailable',
      title: 'Application unavailable or unreachable',
      pattern: /\b5\d\d\b|internal server error|service unavailable|bad gateway|gateway time-?out|timed? ?out|connection (refused|reset|failed)|unreachable|could not connect|\bssl\b|\btls\b|certificate/i,
      why: 'Okta could not complete the call because the application errored, timed out, or its endpoint/certificate could not be reached.',
      checks: ['Check the application\'s status page or server health at the event time.', 'Verify the endpoint URL and TLS certificate in the Okta app\'s Provisioning settings.', 'Retry the failed task once the application is healthy.']
    },
    {
      id: 'provisioning_disabled',
      title: 'Provisioning feature disabled for this action',
      pattern: /provisioning (is )?(not enabled|disabled)|push (is )?(not enabled|disabled)|feature (is )?(not enabled|disabled)|stop deprovisioning/i,
      why: 'The provisioning action (create, update or deactivate) is turned off for this app, so Okta did not send it.',
      checks: ['Open the app\'s Provisioning > To App settings and confirm the needed action is enabled.', 'Check System Log for application.lifecycle.update events that changed provisioning settings.']
    }
  ]);

  const NO_DETAIL_CAUSE = Object.freeze({
    id: 'no_detail',
    title: 'Failure recorded without an error message',
    why: 'Okta logged a failed provisioning event but did not include the error text in System Log. Okta keeps the full error with the failed provisioning task.',
    checks: ['In the Admin Console open Dashboard > Tasks and select this application\'s failed provisioning task to read the error.', 'Or open the app\'s Assignments tab and select the error icon next to the user.', 'After fixing the cause, use Retry on the task.']
  });

  const ERROR_KEY = /error|reason|message|cause|status|response|detail|exception|fault/i;

  // Collect error text Okta recorded on an event. Never includes request URLs or tokens.
  function provisioningErrorText(event) {
    const parts = [];
    const reason = event?.outcome?.reason;
    if (reason) parts.push(String(reason));
    const debug = event?.debugContext?.debugData;
    if (debug && typeof debug === 'object') {
      for (const [key, value] of Object.entries(debug)) {
        if (value === null || value === undefined || typeof value === 'object') continue;
        if (!ERROR_KEY.test(key) || /uri|url|token|cookie|secret|password/i.test(key)) continue;
        const text = String(value).trim();
        if (text && !parts.includes(text)) parts.push(text);
      }
    }
    return parts.join(' | ').slice(0, 1000);
  }

  function isProvisioningFailure(event) {
    if (classify(event) !== CATEGORIES.PROVISIONING) return false;
    return isAdverse(event) || /provision\w*_fail|_failed$/i.test(String(event?.legacyEventType || ''));
  }

  function provisioningCause(event) {
    const text = provisioningErrorText(event);
    if (!text) return NO_DETAIL_CAUSE;
    return PROVISIONING_CAUSES.find(c => c.pattern.test(text)) || {
      id: 'unrecognized',
      title: 'Error recorded but not recognized',
      why: 'Okta recorded an error this tool does not yet recognize. Read the recorded text below.',
      checks: ['Read the error text recorded by Okta below.', 'Check Dashboard > Tasks for the full provisioning error and retry option.']
    };
  }

  function interpretAppUser(appUser) {
    if (!appUser || typeof appUser !== 'object') return [];
    const findings = [];
    const status = String(appUser.status || '').toUpperCase();
    const sync = String(appUser.syncState || '').toUpperCase();
    if (sync === 'ERROR') findings.push({ level: 'error', text: `App-user sync state is ERROR${status ? ` (status ${status})` : ''}. Okta's last sync to this app failed. The full error is in Dashboard > Tasks for this app; fix it and select Retry.` });
    else if (sync === 'OUT_OF_SYNC') findings.push({ level: 'warning', text: 'App-user sync state is OUT_OF_SYNC. Profile changes have not yet been pushed to the app.' });
    else if (sync === 'SYNCING') findings.push({ level: 'info', text: 'App-user sync state is SYNCING. A sync is in progress; re-check shortly.' });
    else if (sync === 'DISABLED') findings.push({ level: 'info', text: 'App-user sync state is DISABLED. Profile push may not be enabled for this app.' });
    else if (sync === 'SYNCHRONIZED') findings.push({ level: 'ok', text: 'App-user sync state is SYNCHRONIZED.' });
    if (status === 'STAGED' || status === 'PENDING') findings.push({ level: 'warning', text: `App-user status is ${status}: the account is not yet active in the app.` });
    if (appUser.lastSync) findings.push({ level: 'info', text: `Last sync recorded by Okta: ${appUser.lastSync}.` });
    return findings;
  }

  function diagnoseProvisioning(events, appUser) {
    const groups = new Map();
    for (const event of Array.isArray(events) ? events : []) {
      if (classify(event) !== CATEGORIES.PROVISIONING) continue;
      const key = event?.transaction?.id || event?.uuid || `${event?.published}|${event?.eventType}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(event);
    }
    const attempts = [...groups.entries()].map(([transactionId, list]) => {
      list.sort((a, b) => String(a.published || '').localeCompare(String(b.published || '')));
      const failed = list.filter(isProvisioningFailure);
      const causes = new Map();
      for (const ev of failed) {
        const cause = provisioningCause(ev);
        if (!causes.has(cause.id)) causes.set(cause.id, { id: cause.id, title: cause.title, why: cause.why, checks: cause.checks, evidence: [] });
        causes.get(cause.id).evidence.push({ published: ev.published || '', eventType: ev.eventType || '', recorded: provisioningErrorText(ev), message: ev.displayMessage || '', eventId: ev.uuid || '' });
      }
      return {
        transactionId,
        transactionType: list[0]?.transaction?.type || '',
        first: list[0]?.published || '',
        last: list[list.length - 1]?.published || '',
        app: list.map(appTarget).find(Boolean)?.displayName || '',
        eventTypes: [...new Set(list.map(e => e.eventType || ''))],
        failed: failed.length > 0,
        causes: [...causes.values()]
      };
    }).sort((a, b) => b.last.localeCompare(a.last));
    const failedAttempts = attempts.filter(a => a.failed);
    const lastFailure = failedAttempts[0]?.last || '';
    const laterSuccess = attempts.find(a => !a.failed && lastFailure && a.last > lastFailure);
    return {
      attempts,
      failedAttempts: failedAttempts.length,
      lastFailure,
      recoveredAt: laterSuccess ? laterSuccess.last : '',
      appUserFindings: interpretAppUser(appUser)
    };
  }

  function rowFor(event) {
    return {
      published: event?.published || '',
      category: classify(event),
      eventType: event?.eventType || '',
      outcome: event?.outcome?.result || '',
      reason: event?.outcome?.reason || '',
      message: event?.displayMessage || '',
      app: appTarget(event)?.displayName || '',
      actor: event?.actor?.alternateId || '',
      ip: event?.client?.ipAddress || '',
      eventId: event?.uuid || '',
      transactionId: event?.transaction?.id || '',
      cause: isProvisioningFailure(event) ? provisioningCause(event).id : ''
    };
  }

  function escapeCsv(value) {
    let s = String(value ?? '');
    // Defuse spreadsheet-formula injection when CSV is opened in Excel/Sheets.
    // A leading tab or carriage return is itself treated as a formula trigger (OWASP).
    if (/^[\t\r]/.test(s) || /^[\s\u0000-\u001f]*[=+@-]/.test(s)) s = "'" + s;
    return `"${s.replace(/"/g, '""')}"`;
  }

  function toCsv(events) {
    const keys = ['published','category','eventType','outcome','reason','message','app','actor','ip','eventId','transactionId','cause'];
    return [keys.map(escapeCsv).join(','), ...events.map(ev => {
      const row = rowFor(ev);
      return keys.map(k => escapeCsv(row[k])).join(',');
    })].join('\r\n') + '\r\n';
  }

  const api = { CATEGORIES, validateIdentifier, validateWindow, buildUserLogUrl, parseNextLink, collectLogs, classify, isFailure, isDenied, isAdverse, appTarget, matchesApp, summarize, triageHints, rowFor, escapeCsv, toCsv, PROVISIONING_CAUSES, provisioningErrorText, isProvisioningFailure, provisioningCause, interpretAppUser, diagnoseProvisioning };
  root.OktaDiagnosticsCore = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

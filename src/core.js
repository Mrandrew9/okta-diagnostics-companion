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

  function isFailure(event) {
    return String(event?.outcome?.result || '').toUpperCase() === 'FAILURE';
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
      const observed = events.filter(e => e?.eventType === eventType && isFailure(e));
      if (observed.length) hints.push({ eventType, count: observed.length, guidance });
    }
    return hints;
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
      transactionId: event?.transaction?.id || ''
    };
  }

  function escapeCsv(value) {
    let s = String(value ?? '');
    // Defuse spreadsheet-formula injection when CSV is opened in Excel/Sheets.
    if (/^[\s\u0000-\u001f]*[=+@-]/.test(s)) s = "'" + s;
    return `"${s.replace(/"/g, '""')}"`;
  }

  function toCsv(events) {
    const keys = ['published','category','eventType','outcome','reason','message','app','actor','ip','eventId','transactionId'];
    return [keys.map(escapeCsv).join(','), ...events.map(ev => {
      const row = rowFor(ev);
      return keys.map(k => escapeCsv(row[k])).join(',');
    })].join('\r\n') + '\r\n';
  }

  const api = { CATEGORIES, validateIdentifier, validateWindow, buildUserLogUrl, parseNextLink, collectLogs, classify, isFailure, appTarget, matchesApp, summarize, triageHints, rowFor, escapeCsv, toCsv };
  root.OktaDiagnosticsCore = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

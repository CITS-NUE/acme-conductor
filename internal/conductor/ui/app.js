// ACME Conductor GUI. Vanilla JavaScript, no build step, no framework.
//
// Rules this file keeps:
// - Everything is rendered through DOM methods (createElement, textContent).
//   Nothing from the API or the URL ever becomes markup.
// - The API is called on the page's own origin only, with a bearer token in
//   oidc mode. The token lives in sessionStorage (one tab, gone when the tab
//   closes) and is never put in a URL or a cookie.
// - Sign-in is the authorization code flow with PKCE as a public client; the
//   only cross-origin request is the code exchange at the provider's token
//   endpoint, which the page's Content-Security-Policy allows explicitly.
'use strict';

(() => {
  const API = '/api/v1alpha1';
  const TOKEN_KEY = 'acme-conductor.token';
  const PKCE_KEY = 'acme-conductor.pkce';
  const REDIRECT_URI = location.origin + '/ui/';
  // The public guide (site/ on GitHub Pages). Links open in a new tab and
  // carry no referrer, so the Conductor's URL never reaches the guide.
  const GUIDE = 'https://cits-nue.github.io/acme-conductor/';

  const state = { config: null, token: null, bindings: null };

  // Display strings live in i18n.js. Only what the page shows is translated:
  // API values, error codes and status values keep their raw form.
  const i18n = window.acmeConductorI18n;
  const tr = (key, vars) => i18n.t(key, vars);

  // ---- DOM helpers ----------------------------------------------------------

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') node.className = v;
        else if (k === 'onclick' || k === 'onsubmit' || k === 'onchange') node.addEventListener(k.slice(2), v);
        else if (k === 'text') node.textContent = v;
        else node.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const c of children) {
      if (c === undefined || c === null || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function main() {
    return document.getElementById('main');
  }

  // flash is a notice shown once, above the next page rendered (the
  // outcome of an action that re-renders the page).
  let flash = null;

  function show(...children) {
    const m = main();
    clear(m);
    if (flash) {
      m.append(flash);
      flash = null;
    }
    m.append(...children);
  }

  function notice(kind, text) {
    return el('p', { class: 'notice ' + kind, text });
  }

  function link(href, text, cls) {
    return el('a', { href, class: cls, text });
  }

  function guideLink(page, text) {
    return el('a', { href: GUIDE + page, target: '_blank', rel: 'noopener noreferrer', text });
  }

  // statusBadge keeps its CSS class from the raw value and shows a
  // translated label, or the raw value when there is none.
  function statusBadge(value) {
    const key = 'status.' + value;
    return el('span', { class: 'status ' + String(value).toLowerCase(), text: i18n.has(key) ? tr(key) : value });
  }

  function enabledBadge(enabled) {
    return statusBadge(enabled ? 'enabled' : 'disabled');
  }

  // targetBadge is the state of a target: retired (docs/adr/0026) wins over
  // enabled/disabled, which a retired target keeps only as history.
  function targetBadge(t) {
    return t.retired ? statusBadge('target-retired') : enabledBadge(t.enabled);
  }

  function pad2(n) {
    return String(n).padStart(2, '0');
  }

  // when shows UTC in ISO form; in Japanese it adds the browser's local time.
  function when(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    const utc = d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
    if (i18n.lang() !== 'ja') return utc;
    const local = d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
    return utc + '（' + tr('common.localTime', { t: local }) + '）';
  }

  // rowOf builds a table row from cells: a cell that already is a td/th is
  // used as it is, anything else is wrapped in a td.
  function rowOf(cells) {
    return el('tr', null, ...cells.map((c) => (c instanceof HTMLTableCellElement ? c : el('td', null, c))));
  }

  function tableHead(headers) {
    return el('thead', null, el('tr', null, ...headers.map((h) => el('th', { text: h }))));
  }

  function table(headers, rows) {
    if (rows.length === 0) return el('p', { class: 'empty', text: tr('common.empty') });
    return el('table', null, tableHead(headers), el('tbody', null, ...rows.map(rowOf)));
  }

  // ---- list filter ----------------------------------------------------------
  //
  // A client-side text filter over the rows a list page has already loaded
  // (no request is made). Its query lives in the hash query string as q, next
  // to the page's own parameters, and is written with history.replaceState so
  // that typing adds no history entries and fires no hashchange (the page is
  // not re-rendered).

  function hashParams() {
    return new URLSearchParams(location.hash.split('?')[1] || '');
  }

  function hashWith(params) {
    const path = location.hash.split('?')[0] || '#/targets';
    const query = params.toString();
    return path + (query ? '?' + query : '');
  }

  function replaceHashParam(name, value) {
    const params = hashParams();
    if (value) params.set(name, value);
    else params.delete(name);
    history.replaceState(null, '', location.pathname + location.search + hashWith(params));
  }

  // normalizeText folds case and full-width forms so that a query matches
  // however it was typed.
  function normalizeText(s) {
    return String(s).normalize('NFKC').toLowerCase();
  }

  const FILTER_DELAY_MS = 120;

  // filteredTable renders a list with a filter box. entries are
  // { cells, extra }: the cells of the row and raw values that are not shown
  // in full (ids, every additional name, error codes). A row is kept when
  // every whitespace-separated term of the query is a substring of its
  // visible cell text plus extra. Only the table body is rebuilt on input,
  // so focus and caret stay in the box. controls are put before the box;
  // limit, when given, adds the hint that only the loaded entries are covered.
  function filteredTable({ headers, entries, controls, limit }) {
    const rows = entries.map((e) => {
      const trow = rowOf(e.cells);
      const visible = Array.from(trow.cells).map((c) => c.textContent);
      return { trow, text: normalizeText(visible.concat(e.extra || []).join(' ')) };
    });
    const tbody = el('tbody');
    const tbl = el('table', null, tableHead(headers), tbody);
    const empty = el('p', { class: 'empty' });
    const count = el('span', { class: 'aside', 'aria-live': 'polite' });
    const box = el('input', { type: 'search', class: 'filter', placeholder: tr('filter.placeholder'), 'aria-label': tr('filter.placeholder'), autocomplete: 'off', spellcheck: 'false', value: hashParams().get('q') || '' });
    const apply = () => {
      const terms = normalizeText(box.value).split(/\s+/).filter((t) => t);
      const kept = rows.filter((r) => terms.every((t) => r.text.includes(t)));
      tbody.replaceChildren(...kept.map((r) => r.trow));
      count.textContent = tr('filter.count', { n: kept.length, m: rows.length });
      tbl.hidden = kept.length === 0;
      empty.hidden = kept.length !== 0;
      empty.textContent = rows.length === 0 ? tr('common.empty') : tr('filter.noMatch');
    };
    let timer = null;
    box.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        apply();
        replaceHashParam('q', box.value.trim());
      }, FILTER_DELAY_MS);
    });
    apply();
    return el('div', { class: 'list' },
      el('div', { class: 'toolbar' }, ...(controls || []), box, count, limit ? el('span', { class: 'aside', text: tr('filter.loadedOnly', { n: limit }) }) : null),
      empty,
      tbl,
    );
  }

  function td(content, cls) {
    return el('td', { class: cls }, content);
  }

  function props(pairs) {
    const dl = el('dl', { class: 'props' });
    for (const [k, v] of pairs) dl.append(el('dt', { text: k }), el('dd', null, v === undefined || v === null || v === '' ? '—' : v));
    return dl;
  }

  let fieldSeq = 0;

  function field(label, input, hint) {
    const id = 'f-' + (++fieldSeq);
    input.id = id;
    const f = el('div', { class: 'field' }, el('label', { for: id, text: label }), input);
    if (hint) f.append(el('div', { class: 'hint', text: hint }));
    return f;
  }

  // select builds a dropdown; label, when given, maps a value to its
  // displayed text (the value itself is what is sent).
  function select(options, value, label) {
    const s = el('select');
    for (const o of options) s.append(el('option', { value: o, selected: o === value, text: label ? label(o) : o }));
    return s;
  }

  function input(type, value, attrs) {
    return el('input', Object.assign({ type, value: value === undefined ? '' : String(value) }, attrs || {}));
  }

  function checkbox(checked) {
    const c = el('input', { type: 'checkbox' });
    c.checked = !!checked;
    return c;
  }

  // ---- names ----------------------------------------------------------------
  //
  // Policies and targets are shown by name (a policy's display name, a
  // target's FQDN), never by id; the id stays in links and in the filter.
  // A policy without a name gets a label derived from its rules.

  function policyLabel(p) {
    if (p.name) return p.name;
    const sfx = p.allowedDnsSuffixes;
    return p.acmeBinding + ' · ' + (sfx.length ? sfx[0] : '—') + (sfx.length > 1 ? ' +' + (sfx.length - 1) : '') + ' · ' + p.keyType;
  }

  // directory loads, once per page render, every policy and every target
  // (retired ones too, so that history resolves) and answers id -> name; an
  // unknown id is shown as it is.
  async function directory() {
    const [targets, policies] = await Promise.all([api('GET', '/targets?retired=include'), api('GET', '/policies')]);
    const tById = new Map(targets.items.map((t) => [t.id, t]));
    const pById = new Map(policies.items.map((p) => [p.id, p]));
    return {
      policies: policies.items,
      target: (id) => (tById.has(id) ? tById.get(id).fqdn : id),
      policy: (id) => (pById.has(id) ? policyLabel(pById.get(id)) : id),
      // policyOfTarget is the label of the policy a target is under, for
      // the filter.
      policyOfTarget: (id) => (tById.has(id) ? (pById.has(tById.get(id).policyRef) ? policyLabel(pById.get(tById.get(id).policyRef)) : tById.get(id).policyRef) : ''),
    };
  }

  async function policyList() {
    return (await api('GET', '/policies')).items;
  }

  // ---- errors ---------------------------------------------------------------

  class ApiError extends Error {
    constructor(status, body) {
      const detail = body && body.error ? body.error : { code: 'http_' + status, message: 'HTTP ' + status };
      super(detail.message || detail.code);
      this.status = status;
      this.code = detail.code;
      this.details = detail.details || {};
    }
  }

  function describe(err) {
    if (err instanceof ApiError) {
      const extra = Object.entries(err.details).map(([k, v]) => k + '=' + v).join(', ');
      return err.code + ': ' + err.message + (extra ? ' (' + extra + ')' : '');
    }
    return err && err.message ? err.message : String(err);
  }

  // codeHint is a one-line plain explanation of an API error code, or null.
  // The code itself is never translated.
  function codeHint(code) {
    const key = 'code.' + code;
    return code && i18n.has(key) ? el('div', { class: 'hint', text: tr(key) }) : null;
  }

  // errorCell shows a run's error code and summary with the hint below.
  function errorCell(e) {
    return el('span', null, el('span', { class: 'mono', text: e.code }), ' ', e.summary, codeHint(e.code));
  }

  // ---- session --------------------------------------------------------------

  function base64url(bytes) {
    let s = '';
    for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomString(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return base64url(buf);
  }

  // decodeClaims reads a JWT payload for display and expiry only. Nothing
  // security-relevant is decided from it: the API verifies the token.
  function decodeClaims(jwt) {
    const part = jwt.split('.')[1] || '';
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (part.length % 4)) % 4);
    return JSON.parse(atob(b64));
  }

  function loadToken() {
    try {
      const raw = sessionStorage.getItem(TOKEN_KEY);
      if (!raw) return null;
      const t = JSON.parse(raw);
      if (!t.access || !t.exp || t.exp * 1000 < Date.now() + 30000) {
        sessionStorage.removeItem(TOKEN_KEY);
        return null;
      }
      return t;
    } catch (e) {
      return null;
    }
  }

  function storeToken(access) {
    const claims = decodeClaims(access);
    const t = { access, exp: claims.exp, name: claims.preferred_username || claims.email || claims.sub || tr('session.user') };
    sessionStorage.setItem(TOKEN_KEY, JSON.stringify(t));
    return t;
  }

  function clearToken() {
    sessionStorage.removeItem(TOKEN_KEY);
    state.token = null;
  }

  async function beginSignIn() {
    const auth = state.config.auth;
    const verifier = randomString(48);
    const challenge = base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const st = randomString(24);
    sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state: st, returnTo: location.hash }));
    const u = new URL(auth.authorizationEndpoint);
    u.searchParams.set('client_id', auth.clientId);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('response_mode', 'query');
    u.searchParams.set('redirect_uri', REDIRECT_URI);
    u.searchParams.set('scope', (auth.scopes || []).join(' '));
    u.searchParams.set('state', st);
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    location.assign(u.toString());
  }

  // completeSignIn handles the return from the provider. It returns true
  // when the URL carried a sign-in response (handled or failed).
  async function completeSignIn() {
    const params = new URLSearchParams(location.search);
    if (!params.has('code') && !params.has('error')) return false;
    const raw = sessionStorage.getItem(PKCE_KEY);
    sessionStorage.removeItem(PKCE_KEY);
    let returnTo = '';
    try {
      if (params.has('error')) throw new Error(tr('signin.refused', { error: params.get('error') }));
      if (!raw) throw new Error(tr('signin.notStarted'));
      const pkce = JSON.parse(raw);
      returnTo = pkce.returnTo || '';
      if (params.get('state') !== pkce.state) throw new Error(tr('signin.mismatch'));
      const auth = state.config.auth;
      const body = new URLSearchParams();
      body.set('grant_type', 'authorization_code');
      body.set('client_id', auth.clientId);
      body.set('code', params.get('code'));
      body.set('redirect_uri', REDIRECT_URI);
      body.set('code_verifier', pkce.verifier);
      const res = await fetch(auth.tokenEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(), credentials: 'omit' });
      const data = await res.json();
      if (!res.ok || !data.access_token) throw new Error(tr('signin.tokenFailed', { error: data.error || res.status }));
      state.token = storeToken(data.access_token);
    } catch (err) {
      history.replaceState(null, '', REDIRECT_URI);
      show(notice('error', tr('signin.failed', { detail: describe(err) })), signInButton());
      return true;
    }
    history.replaceState(null, '', REDIRECT_URI + returnTo);
    return true;
  }

  function signInButton() {
    const auth = state.config.auth;
    if (!auth.clientId) {
      return el('div', { class: 'signin' }, el('p', { text: tr('signin.noClient') }));
    }
    return el('div', { class: 'signin' }, el('p', { text: tr('signin.with', { issuer: auth.issuer }) }), el('button', { class: 'primary', onclick: () => beginSignIn().catch((e) => show(notice('error', describe(e)))) }, tr('session.signIn')));
  }

  function renderSession() {
    const s = document.getElementById('session');
    clear(s);
    if (state.config.auth.mode !== 'oidc') {
      s.append(el('span', { text: tr('session.dev') }));
      return;
    }
    if (state.token) {
      s.append(el('span', { class: 'mono', text: state.token.name }), el('button', { onclick: () => { clearToken(); route(); } }, tr('session.signOut')));
    } else {
      s.append(el('span', { text: tr('session.notSignedIn') }));
    }
  }

  // ---- API ------------------------------------------------------------------

  async function api(method, path, body) {
    const headers = { Accept: 'application/json' };
    if (state.token) headers.Authorization = 'Bearer ' + state.token.access;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(API + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit' });
    let data = null;
    const text = await res.text();
    if (text) {
      try { data = JSON.parse(text); } catch (e) { data = null; }
    }
    if (res.status === 401 && state.config.auth.mode === 'oidc') {
      clearToken();
      renderSession();
    }
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
  }

  async function bindings() {
    if (!state.bindings) state.bindings = await api('GET', '/bindings');
    return state.bindings;
  }

  // ---- views ----------------------------------------------------------------

  function setNav(name) {
    for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', a.dataset.nav === name);
  }

  async function withErrors(fn) {
    try {
      await fn();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && state.config.auth.mode === 'oidc') {
        show(notice('error', tr('session.ended', { detail: describe(err) })), signInButton());
        return;
      }
      show(notice('error', describe(err)));
    }
  }

  // Targets

  async function viewTargets() {
    setNav('targets');
    const showRetired = hashParams().get('retired') === '1';
    const [res, policies] = await Promise.all([api('GET', '/targets' + (showRetired ? '?retired=include' : '')), policyList()]);
    const pName = new Map(policies.map((p) => [p.id, policyLabel(p)]));
    const entries = res.items.map((t) => ({
      cells: [
        el('span', null, link('#/targets/' + encodeURIComponent(t.id), t.fqdn, 'mono'), t.additionalNames.length ? el('span', { class: 'aside', text: tr('targets.moreNames', { n: t.additionalNames.length }) }) : ''),
        targetBadge(t),
        t.owner,
        link('#/policies/' + encodeURIComponent(t.policyRef), pName.get(t.policyRef) || t.policyRef),
        t.executionBinding + ' / ' + t.dnsBinding + ' / ' + t.storeBinding,
        t.certificate ? when(t.certificate.expiresAt) : '—',
        t.lastRun ? el('span', null, statusBadge(t.lastRun.status), ' ', t.lastRun.errorCode ? el('span', { class: 'mono', text: t.lastRun.errorCode }) : '') : '—',
      ],
      extra: [t.id, t.fqdn].concat(t.additionalNames, [t.policyRef, t.lastRun ? t.lastRun.status : '', t.lastRun ? t.lastRun.errorCode || '' : '']),
    }));
    const retiredBox = checkbox(showRetired);
    retiredBox.addEventListener('change', () => {
      const params = hashParams();
      if (retiredBox.checked) params.set('retired', '1');
      else params.delete('retired');
      location.hash = hashWith(params);
    });
    show(
      el('h1', { text: tr('targets.title') }),
      el('div', { class: 'toolbar' }, el('label', null, retiredBox, ' ' + tr('targets.showRetired')), el('span', { class: 'spacer' }), link('#/targets/new', tr('targets.new'), 'button')),
      filteredTable({ headers: [tr('th.fqdn'), tr('th.state'), tr('th.owner'), tr('th.policy'), tr('th.bindings'), tr('th.certExpires'), tr('th.lastRun')], entries }),
    );
  }

  async function viewTarget(id) {
    setNav('targets');
    const [t, runs, dir] = await Promise.all([api('GET', '/targets/' + encodeURIComponent(id)), api('GET', '/targets/' + encodeURIComponent(id) + '/runs?limit=50'), directory()]);
    const status = el('div');
    const refresh = () => route();
    const act = (label, method, path, cls, body) => el('button', {
      class: cls,
      onclick: async () => {
        clear(status);
        try {
          await api(method, path, body);
          refresh();
        } catch (err) {
          status.append(notice('error', describe(err)));
        }
      },
    }, label);
    const cert = t.certificate;
    // A retired target is history only: no actions, no edit form, no ACME
    // account section.
    const account = t.retired ? null : await targetAccountSection(t);
    show(
      el('h1', null, el('span', { class: 'mono', text: t.fqdn }), ' ', targetBadge(t)),
      status,
      t.retired ? notice('', tr('retired.banner', { at: when(t.retiredAt), by: t.retiredBy || '—' })) : nextStep(t, account),
      t.retired ? '' : el('div', { class: 'toolbar' },
        act(tr('target.runNow'), 'POST', '/targets/' + encodeURIComponent(t.id) + '/runs', 'primary', { revision: t.revision }),
        t.enabled ? act(tr('target.disable'), 'POST', '/targets/' + encodeURIComponent(t.id) + '/disable', 'danger') : act(tr('target.enable'), 'POST', '/targets/' + encodeURIComponent(t.id) + '/enable'),
      ),
      props([
        [tr('target.id'), el('span', { class: 'mono', text: t.id })],
        [tr('target.additional'), t.additionalNames.length ? el('span', { class: 'mono', text: t.additionalNames.join(', ') }) : tr('target.singleName')],
        [tr('target.owner'), t.owner],
        [tr('target.policy'), link('#/policies/' + encodeURIComponent(t.policyRef), dir.policy(t.policyRef))],
        [tr('target.exec'), t.executionBinding],
        [tr('target.dns'), t.dnsBinding],
        [tr('target.store'), t.storeBinding],
        [tr('target.revision'), String(t.revision)],
        [tr('target.createdUpdated'), when(t.createdAt) + ' / ' + when(t.updatedAt)],
        [tr('target.certificate'), cert ? el('span', null, tr('target.certExpires') + when(cert.expiresAt) + tr('target.certStored'), el('span', { class: 'mono', text: cert.storeObjectRef }), tr('target.certFingerprint'), el('span', { class: 'mono', text: cert.fingerprintSha256 })) : tr('target.certNone')],
        [tr('target.lastSuccess'), cert ? link('#/runs/' + encodeURIComponent(cert.lastSucceededRunId), cert.lastSucceededRunId, 'mono') : '—'],
      ].concat(t.retired ? [[tr('target.retired'), when(t.retiredAt) + ' / ' + (t.retiredBy || '—')]] : [])),
      account ? account.node : '',
      t.retired ? '' : el('h2', { text: tr('common.edit') }),
      t.retired ? '' : await targetForm(t),
      t.retired ? '' : retirePanel(t),
      el('h2', { text: tr('common.runs') }),
      runsTable(runs.items, false, dir),
    );
  }

  // retirePanel is the way out for a target that is not needed any more
  // (docs/adr/0026): a disabled target is retired after its FQDN is typed
  // in, since there is no way back. An enabled one only says to disable
  // first.
  function retirePanel(t) {
    if (t.enabled) return el('div', null, el('h2', { text: tr('retire.title') }), el('p', { class: 'aside', text: tr('retire.needDisable') }));
    const status = el('div');
    const confirm = input('text', '', { placeholder: t.fqdn, autocomplete: 'off', spellcheck: 'false', 'aria-label': tr('retire.confirmLabel', { fqdn: t.fqdn }) });
    const button = el('button', {
      class: 'danger',
      disabled: true,
      onclick: async () => {
        clear(status);
        button.disabled = true;
        try {
          await api('POST', '/targets/' + encodeURIComponent(t.id) + '/retire');
          flash = notice('ok', tr('retire.done'));
          route();
        } catch (err) {
          status.append(notice('error', describe(err)));
          button.disabled = confirm.value.trim().toLowerCase() !== t.fqdn;
        }
      },
    }, tr('retire.button'));
    confirm.addEventListener('input', () => { button.disabled = confirm.value.trim().toLowerCase() !== t.fqdn; });
    return el('div', { class: 'panel retire' },
      el('h2', { text: tr('retire.title') }),
      el('p', { text: tr('retire.intro') }),
      el('ul', null, ...['retire.b1', 'retire.b2', 'retire.b3', 'retire.b4'].map((k) => el('li', { text: tr(k) }))),
      el('p', null, el('strong', { text: tr('retire.final') })),
      status,
      el('div', { class: 'field' }, el('label', { text: tr('retire.confirmLabel', { fqdn: t.fqdn }) }), confirm),
      el('div', { class: 'actions' }, button),
    );
  }

  // nextStep tells the operator what to do next, from state the page has
  // already fetched: the target (with its last run and certificate) and,
  // for a per-target binding, the target's ACME account.
  function nextStep(t, account) {
    const last = t.lastRun;
    const runLink = last ? link('#/runs/' + encodeURIComponent(last.id), last.id, 'mono') : null;
    const acct = account ? account.acct : null;
    let kind = '';
    let body;
    if (acct && !acct.activeGeneration && !acct.pending) {
      body = [tr('next.eab')];
    } else if (!t.enabled) {
      body = [tr(acct && acct.pending ? 'next.enableEab' : 'next.enable')];
    } else if (last && ['queued', 'starting', 'running'].includes(last.status)) {
      body = [tr('next.running'), runLink];
    } else if (last && last.status === 'failed') {
      kind = 'error';
      body = [tr('next.failed', { code: last.errorCode || '—' }), runLink, ' ', tr('next.failedGuide'), guideLink('upki-guide.html#troubleshooting', tr('next.failedGuideLink')), codeHint(last.errorCode)];
    } else if (acct && acct.pending) {
      body = [tr('next.pendingEab')];
    } else if (last && last.status === 'succeeded' && t.certificate) {
      kind = 'ok';
      body = [tr('next.done'), el('span', { class: 'mono', text: t.certificate.storeObjectRef }), tr('next.doneTail'), ' ', guideLink('certificate-usage.html', tr('next.usageLink'))];
    } else if (!last) {
      body = [tr('next.noRun')];
    } else {
      return null;
    }
    return el('div', { class: 'notice next ' + kind }, el('strong', { text: tr('next.title') }), ' ', ...body);
  }

  async function targetForm(t) {
    const b = await bindings();
    const policyItems = await policyList();
    const policies = policyItems.map((p) => p.id);
    const policyNames = new Map(policyItems.map((p) => [p.id, policyLabel(p)]));
    const isNew = !t;
    const fqdn = input('text', t ? t.fqdn : '', { placeholder: 'host.example.ac.jp', required: true, disabled: !isNew });
    const additional = el('textarea', { rows: 3, placeholder: 'www.example.ac.jp\nalias.example.ac.jp' });
    additional.value = t ? t.additionalNames.join('\n') : '';
    const additionalNames = () => additional.value.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s);
    const owner = input('text', t ? t.owner : '', { required: true, maxlength: 128 });
    const policy = select(policies, t ? t.policyRef : policies[0], (id) => policyNames.get(id));
    const exec = select(b.execution, t ? t.executionBinding : b.execution[0]);
    const dns = select(b.dns, t ? t.dnsBinding : b.dns[0]);
    const store = select(b.store, t ? t.storeBinding : b.store[0]);
    const enabled = checkbox(t ? t.enabled : true);
    const status = el('div');
    const form = el('form', {
      class: 'panel',
      onsubmit: async (ev) => {
        ev.preventDefault();
        clear(status);
        try {
          if (isNew) {
            const created = await api('POST', '/targets', {
              fqdn: fqdn.value.trim(), additionalNames: additionalNames(), owner: owner.value, policyRef: policy.value,
              executionBinding: exec.value, dnsBinding: dns.value, storeBinding: store.value, enabled: enabled.checked,
            });
            location.hash = '#/targets/' + encodeURIComponent(created.id);
          } else {
            await api('PUT', '/targets/' + encodeURIComponent(t.id), {
              revision: t.revision, additionalNames: additionalNames(), owner: owner.value, policyRef: policy.value,
              executionBinding: exec.value, dnsBinding: dns.value, storeBinding: store.value, enabled: enabled.checked,
            });
            route();
          }
        } catch (err) {
          status.append(notice('error', describe(err)));
        }
      },
    },
    status,
    field(tr('form.fqdn'), fqdn, isNew ? tr('form.fqdnHintNew') : tr('form.fqdnHintEdit')),
    field(tr('form.additional'), additional, tr('form.additionalHint')),
    field(tr('form.owner'), owner, tr('form.ownerHint')),
    field(tr('form.policy'), policy, tr('form.policyHint')),
    field(tr('form.exec'), exec, tr('form.execHint')),
    field(tr('form.dns'), dns, tr('form.dnsHint')),
    field(tr('form.store'), store, tr('form.storeHint')),
    field(tr('form.enabled'), enabled, tr('form.enabledHint')),
    el('div', { class: 'actions' }, el('button', { class: 'primary', type: 'submit' }, isNew ? tr('form.createTarget') : tr('common.saveChanges'))),
    );
    if (policies.length === 0) form.prepend(notice('error', tr('form.needPolicy')));
    return form;
  }

  async function viewNewTarget() {
    setNav('targets');
    show(el('h1', { text: tr('targets.newTitle') }), await targetForm(null));
  }

  // Policies

  async function viewPolicies() {
    setNav('policies');
    const res = await api('GET', '/policies');
    const entries = res.items.map((p) => ({
      cells: [
        link('#/policies/' + encodeURIComponent(p.id), policyLabel(p)),
        enabledBadge(p.enabled),
        td(p.allowedDnsSuffixes.join(', '), 'mono'),
        p.allowWildcard ? tr('common.yes') : tr('common.no'),
        p.acmeBinding,
        tr('common.days', { n: p.renewBeforeDays }),
        p.keyType,
        String(p.maxSANs),
      ],
      extra: [p.id, p.name],
    }));
    show(
      el('h1', { text: tr('policies.title') }),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), link('#/policies/new', tr('policies.new'), 'button')),
      filteredTable({ headers: [tr('th.name'), tr('th.state'), tr('th.suffixes'), tr('th.wildcard'), tr('th.acmeBinding'), tr('th.renew'), tr('th.key'), tr('th.maxSans')], entries }),
    );
  }

  async function policyForm(p) {
    const b = await bindings();
    const isNew = !p;
    const name = input('text', p ? p.name : '', { required: isNew, maxlength: 64, autocomplete: 'off' });
    const suffixes = el('textarea', { rows: 3, placeholder: 'example.ac.jp\nlab.example.ac.jp' });
    suffixes.value = p ? p.allowedDnsSuffixes.join('\n') : '';
    const wildcard = checkbox(p ? p.allowWildcard : false);
    const acme = select(b.acme, p ? p.acmeBinding : b.acme[0]);
    const renew = input('number', p ? p.renewBeforeDays : 30, { min: 1, max: 365 });
    const keyType = select(['ec256', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'], p ? p.keyType : 'ec256');
    const maxSANs = input('number', p ? p.maxSANs : 1, { min: 1, max: 100 });
    const enabled = checkbox(p ? p.enabled : true);
    const status = el('div');
    const body = () => ({
      name: name.value.trim(),
      allowedDnsSuffixes: suffixes.value.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s),
      allowWildcard: wildcard.checked,
      acmeBinding: acme.value,
      renewBeforeDays: Number(renew.value),
      keyType: keyType.value,
      maxSANs: Number(maxSANs.value),
      enabled: enabled.checked,
    });
    return el('form', {
      class: 'panel',
      onsubmit: async (ev) => {
        ev.preventDefault();
        clear(status);
        try {
          if (isNew) {
            const created = await api('POST', '/policies', body());
            location.hash = '#/policies/' + encodeURIComponent(created.id);
          } else {
            await api('PUT', '/policies/' + encodeURIComponent(p.id), body());
            route();
          }
        } catch (err) {
          status.append(notice('error', describe(err)));
        }
      },
    },
    status,
    field(tr('policy.name'), name, tr('policy.nameHint')),
    field(tr('policy.suffixes'), suffixes, tr('policy.suffixesHint')),
    field(tr('policy.wildcard'), wildcard),
    field(tr('policy.acme'), acme, tr('policy.acmeHint')),
    field(tr('policy.renew'), renew, tr('policy.renewHint')),
    field(tr('policy.keyType'), keyType),
    field(tr('policy.maxSans'), maxSANs, tr('policy.maxSansHint')),
    field(tr('policy.enabled'), enabled),
    el('div', { class: 'actions' }, el('button', { class: 'primary', type: 'submit' }, isNew ? tr('policy.create') : tr('common.saveChanges'))),
    );
  }

  async function viewPolicy(id) {
    setNav('policies');
    const [p, targets] = await Promise.all([api('GET', '/policies/' + encodeURIComponent(id)), api('GET', '/targets?policyRef=' + encodeURIComponent(id))]);
    show(
      el('h1', null, policyLabel(p), ' ', enabledBadge(p.enabled)),
      props([
        [tr('policy.id'), el('span', { class: 'mono', text: p.id })],
        [tr('policy.createdUpdated'), when(p.createdAt) + ' / ' + when(p.updatedAt)],
        [tr('policy.targetCount'), String(targets.items.length)],
      ]),
      el('h2', { text: tr('common.edit') }),
      notice('', tr('policy.changeNotice')),
      await policyForm(p),
      el('h2', { text: tr('policy.targets') }),
      table([tr('th.fqdn'), tr('th.state'), tr('th.owner')], targets.items.map((t) => [td(link('#/targets/' + encodeURIComponent(t.id), t.fqdn), 'mono'), enabledBadge(t.enabled), t.owner])),
    );
  }

  async function viewNewPolicy() {
    setNav('policies');
    show(el('h1', { text: tr('policies.newTitle') }), await policyForm(null));
  }

  // Runs

  function runEntries(items, withTarget, dir) {
    const headers = [tr('th.run'), tr('th.status'), tr('th.requested'), tr('th.finished'), tr('th.action'), tr('th.error'), tr('th.requestedBy')];
    if (withTarget) headers.splice(1, 0, tr('th.target'));
    const entries = items.map((r) => {
      const cells = [
        td(link('#/runs/' + encodeURIComponent(r.id), r.id), 'mono'),
        statusBadge(r.status),
        when(r.requestedAt),
        when(r.finishedAt),
        r.action || '—',
        r.error ? errorCell(r.error) : '—',
        r.requestedBy,
      ];
      if (withTarget) cells.splice(1, 0, td(link('#/targets/' + encodeURIComponent(r.targetId), dir.target(r.targetId)), 'mono'));
      return { cells, extra: [r.id, r.targetId, dir.target(r.targetId), dir.policyOfTarget(r.targetId), r.status, r.error ? r.error.code : '', r.requestedByAuthority || '', r.externalExecutionId || ''] };
    });
    return { headers, entries };
  }

  function runsTable(items, withTarget, dir) {
    const { headers, entries } = runEntries(items, withTarget, dir);
    return table(headers, entries.map((e) => e.cells));
  }

  const RUNS_LIMIT = 100;

  async function viewRuns() {
    setNav('runs');
    const status = hashParams().get('status') || '';
    const [res, dir] = await Promise.all([api('GET', '/runs?limit=' + RUNS_LIMIT + (status ? '&status=' + encodeURIComponent(status) : '')), directory()]);
    const sel = select(['', 'queued', 'starting', 'running', 'succeeded', 'failed', 'cancelled'], status, (v) => (v ? tr('status.' + v) : tr('common.all')));
    sel.addEventListener('change', () => {
      const params = hashParams();
      if (sel.value) params.set('status', sel.value);
      else params.delete('status');
      location.hash = hashWith(params);
    });
    const { headers, entries } = runEntries(res.items, true, dir);
    show(
      el('h1', { text: tr('runs.title') }),
      filteredTable({ headers, entries, controls: [el('label', { text: tr('common.status') + ' ' }), sel], limit: RUNS_LIMIT }),
    );
  }

  async function viewRun(id) {
    setNav('runs');
    const [r, dir] = await Promise.all([api('GET', '/runs/' + encodeURIComponent(id)), directory()]);
    const status = el('div');
    const cancellable = ['queued', 'starting', 'running'].includes(r.status);
    show(
      el('h1', null, tr('run.title'), el('span', { class: 'mono', text: r.id }), ' ', statusBadge(r.status)),
      status,
      el('div', { class: 'toolbar' }, cancellable ? el('button', {
        class: 'danger',
        onclick: async () => {
          clear(status);
          try {
            await api('POST', '/runs/' + encodeURIComponent(r.id) + '/cancel');
            route();
          } catch (err) {
            status.append(notice('error', describe(err)));
          }
        },
      }, tr('run.cancel')) : null),
      props([
        [tr('run.target'), link('#/targets/' + encodeURIComponent(r.targetId), dir.target(r.targetId), 'mono')],
        [tr('run.revision'), String(r.targetRevision)],
        [tr('run.requestedBy'), el('span', null, el('span', { class: 'mono', text: r.requestedBy }), r.requestedByAuthority ? ' @ ' : '', r.requestedByAuthority ? el('span', { class: 'mono', text: r.requestedByAuthority }) : '')],
        [tr('run.times'), when(r.requestedAt) + ' / ' + when(r.startedAt) + ' / ' + when(r.finishedAt)],
        [tr('run.action'), r.action],
        [tr('run.expires'), r.expiresAt ? when(r.expiresAt) : undefined],
        [tr('run.fingerprint'), r.fingerprintSha256 ? el('span', { class: 'mono', text: r.fingerprintSha256 }) : undefined],
        [tr('run.storeObject'), r.storeObjectRef ? el('span', { class: 'mono', text: r.storeObjectRef }) : undefined],
        [tr('run.error'), r.error ? errorCell(r.error) : undefined],
        [tr('run.execution'), r.externalExecutionId ? el('span', { class: 'mono', text: r.externalExecutionId }) : undefined],
      ]),
    );
  }

  // Audit

  const AUDIT_LIMIT = 200;

  async function viewAudit() {
    setNav('audit');
    const [res, dir] = await Promise.all([api('GET', '/audit?limit=' + AUDIT_LIMIT), directory()]);
    const entries = res.items.map((e) => ({
      cells: [
        when(e.time),
        td(e.actor, 'mono'),
        e.actorAuthority ? td(e.actorAuthority, 'mono') : '—',
        td(e.action, 'mono'),
        e.targetId ? td(link('#/targets/' + encodeURIComponent(e.targetId), dir.target(e.targetId)), 'mono') : '—',
        e.runId ? td(link('#/runs/' + encodeURIComponent(e.runId), e.runId), 'mono') : '—',
        e.policyId ? link('#/policies/' + encodeURIComponent(e.policyId), dir.policy(e.policyId)) : '—',
        e.detail,
      ],
      extra: [e.id, e.time, e.targetId || '', e.policyId || '', e.targetId ? dir.policyOfTarget(e.targetId) : ''],
    }));
    show(
      el('h1', { text: tr('audit.title') }),
      filteredTable({ headers: [tr('th.time'), tr('th.actor'), tr('th.authority'), tr('th.action'), tr('th.target'), tr('th.runShort'), tr('th.policy'), tr('th.detail')], entries, limit: AUDIT_LIMIT }),
    );
  }

  // ---- ACME account provisioning (issue #42) --------------------------------
  //
  // The kid/hmac an operator types here are sealed to the Runner's
  // provisioning key in this tab (provision.js) before anything is sent:
  // the Conductor never sees them, and this page never renders one back.

  async function provisioningKey() {
    try {
      return await api('GET', '/account-provisioning/key');
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return null;
      throw err;
    }
  }

  function nextGeneration(acct) {
    return acct.generations.length ? acct.generations[0].generation + 1 : 1;
  }

  // An account is { binding, scope, path, activeGeneration, pending,
  // generations }: scope is '' and path '/acme-bindings/<b>' for a
  // binding's own account, or the target id and
  // '/acme-bindings/<b>/targets/<id>' for a target's account on a binding
  // that keeps one account per target (sealed with the scoped version).
  function bindingAccount(b) {
    return { binding: b.name, scope: '', path: '/acme-bindings/' + encodeURIComponent(b.name), activeGeneration: b.activeGeneration, pending: b.pending, generations: b.generations };
  }

  function targetAccount(binding, a) {
    return { binding, scope: a.targetId, path: '/acme-bindings/' + encodeURIComponent(binding) + '/targets/' + encodeURIComponent(a.targetId), activeGeneration: a.activeGeneration, pending: a.pending, generations: a.generations };
  }

  // provisioningRunNotice says which run carries a provisioning request
  // just recorded, or why none was started.
  function provisioningRunNotice(run) {
    if (!run) return null;
    if (run.started) {
      return el('p', { class: 'notice' }, tr('eab.recorded'), link('#/runs/' + encodeURIComponent(run.runId), run.runId, 'mono'), tr('eab.recordedStarted'));
    }
    const parts = [tr('eab.recordedNoRun', { reason: run.reason })];
    if (run.runId) parts.push(tr('eab.runWord'), link('#/runs/' + encodeURIComponent(run.runId), run.runId, 'mono'), '.');
    return el('p', { class: 'notice' }, ...parts);
  }

  function provisioningForm(keyInfo, acct, onDone) {
    const kid = input('text', '', { autocomplete: 'off' });
    const hmac = input('password', '', { autocomplete: 'off' });
    const status = el('div');
    const clearInputs = () => { kid.value = ''; hmac.value = ''; };
    return el('form', {
      class: 'panel',
      onsubmit: async (ev) => {
        ev.preventDefault();
        clear(status);
        const k = kid.value, h = hmac.value;
        try {
          const generation = nextGeneration(acct);
          const encryptedCredential = await acmeConductorSealEAB(keyInfo, acct.binding, generation, k, h, acct.scope);
          clearInputs();
          const res = await api('POST', acct.path + '/provisioning', { accountGeneration: generation, encryptedCredential });
          flash = provisioningRunNotice(res.run);
          onDone();
        } catch (err) {
          clearInputs();
          status.append(notice('error', describe(err)));
        }
      },
    },
    status,
    el('p', { class: 'hint', text: tr('eab.sealed', { keyId: keyInfo.keyId, scope: acct.scope ? tr('eab.sealedScope') : '' }) }),
    field(tr('eab.kid'), kid),
    field(tr('eab.hmac'), hmac, tr('eab.hmacHint')),
    el('div', { class: 'actions' }, el('button', { class: 'primary', type: 'submit' }, tr('eab.submit', { n: nextGeneration(acct) }))),
    );
  }

  // accountDetails lists an account's generations, with the cancel button
  // for an unattached pending one.
  function accountDetails(acct, refresh) {
    const parts = [
      props([
        [tr('eab.activeGen'), acct.activeGeneration || '—'],
        [tr('eab.pending'), acct.pending ? tr('eab.pendingText', { gen: acct.pending.generation, status: acct.pending.status, attached: acct.pending.runId ? tr('eab.attached', { run: acct.pending.runId }) : '' }) : '—'],
      ]),
      table([tr('th.generation'), tr('th.status'), tr('th.keyId'), tr('th.requestedBy'), tr('th.created'), tr('th.activated')],
        acct.generations.map((g) => [g.generation, statusBadge(g.status), td(g.keyId, 'mono'), g.requestedBy, when(g.createdAt), when(g.activatedAt)])),
    ];
    if (acct.pending && !acct.pending.runId) {
      parts.push(el('div', { class: 'actions' }, el('button', {
        class: 'danger',
        onclick: async () => {
          try {
            await api('DELETE', acct.path + '/provisioning/' + encodeURIComponent(acct.pending.generation));
            refresh();
          } catch (err) {
            parts.push(notice('error', describe(err)));
          }
        },
      }, tr('eab.cancel', { n: acct.pending.generation }))));
    }
    return parts;
  }

  // accountForm is the provisioning form for acct, or why there is none.
  function accountForm(keyInfo, acct, eabRequired, x25519Ok, refresh) {
    if (!eabRequired) {
      return [el('p', { class: 'hint', text: tr('eab.dropped') })];
    }
    if (acct.pending) {
      return [el('p', { class: 'hint', text: tr('eab.alreadyPending') })];
    }
    if (!x25519Ok) {
      return [notice('error', tr('eab.noX25519'))];
    }
    return [el('h3', { text: tr('eab.formTitle') }), provisioningForm(keyInfo, acct, refresh)];
  }

  function acmeBindingPanel(keyInfo, b, targets, x25519Ok, refresh) {
    const parts = [el('h2', { text: b.name })];
    if (b.targetScoped) {
      const byId = new Map(targets.map((t) => [t.id, t]));
      parts.push(
        el('p', { class: 'hint', text: tr('eab.perTarget') }),
        table([tr('th.target'), tr('th.activeGeneration'), tr('th.pending')], b.targets.map((a) => {
          const t = byId.get(a.targetId);
          return [link('#/targets/' + encodeURIComponent(a.targetId), t ? t.fqdn : a.targetId, 'mono'), a.activeGeneration || '—', a.pending ? String(a.pending.generation) : '—'];
        })),
      );
      // A binding-wide account left from before the binding became
      // target-scoped is still listed, to be seen and cancelled.
      if (b.generations.length) {
        parts.push(el('h3', { text: tr('eab.bindingWide') }), ...accountDetails(bindingAccount(b), refresh));
      }
      return el('div', { class: 'panel' }, ...parts);
    }
    const acct = bindingAccount(b);
    parts.push(...accountDetails(acct, refresh), ...accountForm(keyInfo, acct, b.externalAccountBinding, x25519Ok, refresh));
    return el('div', { class: 'panel' }, ...parts);
  }

  // The page lists the bindings whose CA takes an EAB, plus any other
  // binding still holding a pending request (left from before it was
  // dropped from accountProvisioning.bindings) so that it can be
  // cancelled. A binding whose CA takes no EAB has nothing to show here.
  async function viewEAB() {
    setNav('eab');
    const keyInfo = await provisioningKey();
    const heading = el('h1', { text: tr('eab.title') });
    if (!keyInfo) {
      show(heading, notice('error', tr('eab.notConfigured')));
      return;
    }
    const [res, targets, x25519Ok] = await Promise.all([api('GET', '/acme-bindings'), api('GET', '/targets?retired=include'), acmeConductorX25519Supported()]);
    const items = res.items.filter((b) => b.externalAccountBinding || b.pending || b.targets.some((a) => a.pending));
    const refresh = () => withErrors(() => viewEAB());
    show(
      heading,
      el('p', { class: 'notice', text: tr('eab.notice') }),
      ...(items.length
        ? items.map((b) => acmeBindingPanel(keyInfo, b, targets.items, x25519Ok, refresh))
        : [el('p', { class: 'hint', text: tr('eab.noneListed') })]),
    );
  }

  // targetAccountSection is the target page's ACME account section when
  // the target's binding keeps one account per target, as { node, acct };
  // null otherwise.
  async function targetAccountSection(t) {
    const keyInfo = await provisioningKey();
    if (!keyInfo) return null;
    const policy = await api('GET', '/policies/' + encodeURIComponent(t.policyRef));
    const b = await api('GET', '/acme-bindings/' + encodeURIComponent(policy.acmeBinding));
    if (!b.targetScoped) return null;
    const [a, x25519Ok] = await Promise.all([
      api('GET', '/acme-bindings/' + encodeURIComponent(b.name) + '/targets/' + encodeURIComponent(t.id)),
      acmeConductorX25519Supported(),
    ]);
    const acct = targetAccount(b.name, a);
    const refresh = () => route();
    const node = el('div', null,
      el('h2', { text: tr('eab.targetAccount', { name: b.name }) }),
      el('p', { class: 'hint' }, tr('eab.targetHint'), ' ', guideLink('upki-guide.html#step7', tr('eab.guideLink'))),
      ...accountDetails(acct, refresh),
      ...accountForm(keyInfo, acct, b.externalAccountBinding, x25519Ok, refresh),
    );
    return { node, acct };
  }

  // ---- routing --------------------------------------------------------------

  const routes = [
    [/^#\/targets\/new$/, () => viewNewTarget()],
    [/^#\/targets\/([A-Za-z0-9_-]+)$/, (m) => viewTarget(m[1])],
    [/^#\/targets(\?.*)?$/, () => viewTargets()],
    [/^#\/policies\/new$/, () => viewNewPolicy()],
    [/^#\/policies\/([A-Za-z0-9_-]+)$/, (m) => viewPolicy(m[1])],
    [/^#\/policies(\?.*)?$/, () => viewPolicies()],
    [/^#\/runs\/([A-Za-z0-9_-]+)$/, (m) => viewRun(m[1])],
    [/^#\/runs(\?.*)?$/, () => viewRuns()],
    [/^#\/audit(\?.*)?$/, () => viewAudit()],
    [/^#\/eab$/, () => viewEAB()],
    // The page's former address, kept for bookmarks.
    [/^#\/acme-bindings$/, () => { location.hash = '#/eab'; }],
  ];

  function route() {
    renderSession();
    if (state.config.auth.mode === 'oidc' && !state.token) {
      show(signInButton());
      return;
    }
    const hash = location.hash || '#/targets';
    for (const [re, fn] of routes) {
      const m = re.exec(hash);
      if (m) {
        withErrors(() => fn(m));
        return;
      }
    }
    location.hash = '#/targets';
  }

  // applyStatic sets the language-dependent parts of index.html: <html lang>,
  // the title, every [data-i18n] element and the language selector.
  function applyStatic() {
    document.documentElement.lang = i18n.lang();
    document.title = tr('app.title');
    for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = tr(node.dataset.i18n);
    const sel = document.getElementById('lang');
    if (sel) {
      sel.value = i18n.lang();
      sel.setAttribute('aria-label', tr('lang.label'));
    }
  }

  function initLanguage() {
    applyStatic();
    const sel = document.getElementById('lang');
    if (!sel) return;
    sel.addEventListener('change', () => {
      i18n.setLang(sel.value);
      applyStatic();
      if (state.config) route();
    });
  }

  async function start() {
    initLanguage();
    try {
      const res = await fetch('/ui/config', { headers: { Accept: 'application/json' }, credentials: 'omit' });
      if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => null));
      state.config = await res.json();
    } catch (err) {
      show(notice('error', tr('config.failed', { detail: describe(err) })));
      return;
    }
    if (state.config.auth.mode === 'oidc') {
      state.token = loadToken();
      if (await completeSignIn()) {
        if (!state.token) return;
      }
    }
    window.addEventListener('hashchange', route);
    route();
  }

  start();
})();

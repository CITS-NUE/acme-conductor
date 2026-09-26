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

  const state = { config: null, token: null, bindings: null };

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

  function show(...children) {
    const m = main();
    clear(m);
    m.append(...children);
  }

  function notice(kind, text) {
    return el('p', { class: 'notice ' + kind, text });
  }

  function link(href, text, cls) {
    return el('a', { href, class: cls, text });
  }

  function statusBadge(value) {
    return el('span', { class: 'status ' + String(value).toLowerCase(), text: value });
  }

  function enabledBadge(enabled) {
    return statusBadge(enabled ? 'enabled' : 'disabled');
  }

  function when(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? String(iso) : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  }

  function table(headers, rows) {
    if (rows.length === 0) return el('p', { class: 'empty', text: 'Nothing here yet.' });
    const thead = el('thead', null, el('tr', null, ...headers.map((h) => el('th', { text: h }))));
    const tbody = el('tbody', null, ...rows.map((cells) => el('tr', null, ...cells.map((c) => (c instanceof HTMLTableCellElement ? c : el('td', null, c))))));
    return el('table', null, thead, tbody);
  }

  function td(content, cls) {
    return el('td', { class: cls }, content);
  }

  function props(pairs) {
    const dl = el('dl', { class: 'props' });
    for (const [k, v] of pairs) dl.append(el('dt', { text: k }), el('dd', null, v === undefined || v === null || v === '' ? '—' : v));
    return dl;
  }

  function field(label, input, hint) {
    const id = 'f-' + label.replace(/[^a-z0-9]+/gi, '-').toLowerCase();
    input.id = id;
    const f = el('div', { class: 'field' }, el('label', { for: id, text: label }), input);
    if (hint) f.append(el('div', { class: 'hint', text: hint }));
    return f;
  }

  function select(options, value) {
    const s = el('select');
    for (const o of options) s.append(el('option', { value: o, selected: o === value, text: o }));
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
    const t = { access, exp: claims.exp, name: claims.preferred_username || claims.email || claims.sub || 'signed in' };
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
      if (params.has('error')) throw new Error('the identity provider refused sign-in: ' + params.get('error'));
      if (!raw) throw new Error('no sign-in was started in this tab');
      const pkce = JSON.parse(raw);
      returnTo = pkce.returnTo || '';
      if (params.get('state') !== pkce.state) throw new Error('the sign-in response does not match the request');
      const auth = state.config.auth;
      const body = new URLSearchParams();
      body.set('grant_type', 'authorization_code');
      body.set('client_id', auth.clientId);
      body.set('code', params.get('code'));
      body.set('redirect_uri', REDIRECT_URI);
      body.set('code_verifier', pkce.verifier);
      const res = await fetch(auth.tokenEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(), credentials: 'omit' });
      const data = await res.json();
      if (!res.ok || !data.access_token) throw new Error('the token request failed: ' + (data.error || res.status));
      state.token = storeToken(data.access_token);
    } catch (err) {
      history.replaceState(null, '', REDIRECT_URI);
      show(notice('error', 'Sign-in failed. ' + describe(err)), signInButton());
      return true;
    }
    history.replaceState(null, '', REDIRECT_URI + returnTo);
    return true;
  }

  function signInButton() {
    const auth = state.config.auth;
    if (!auth.clientId) {
      return el('div', { class: 'signin' }, el('p', { text: 'This deployment has no GUI client registered (server.auth.oidc.clientId). Use the API with a token obtained elsewhere.' }));
    }
    return el('div', { class: 'signin' }, el('p', { text: 'Sign in with ' + auth.issuer + ' to continue.' }), el('button', { class: 'primary', onclick: () => beginSignIn().catch((e) => show(notice('error', describe(e)))) }, 'Sign in'));
  }

  function renderSession() {
    const s = document.getElementById('session');
    clear(s);
    if (state.config.auth.mode !== 'oidc') {
      s.append(el('span', { text: 'localhost-dev (every local caller is an administrator)' }));
      return;
    }
    if (state.token) {
      s.append(el('span', { class: 'mono', text: state.token.name }), el('button', { onclick: () => { clearToken(); route(); } }, 'Sign out'));
    } else {
      s.append(el('span', { text: 'not signed in' }));
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
        show(notice('error', 'Your session has ended (' + describe(err) + ').'), signInButton());
        return;
      }
      show(notice('error', describe(err)));
    }
  }

  // Targets

  async function viewTargets() {
    setNav('targets');
    const res = await api('GET', '/targets');
    const rows = res.items.map((t) => [
      td(link('#/targets/' + encodeURIComponent(t.id), t.fqdn), 'mono'),
      enabledBadge(t.enabled),
      t.owner,
      td(link('#/policies/' + encodeURIComponent(t.policyRef), t.policyRef), 'mono'),
      t.executionBinding + ' / ' + t.dnsBinding + ' / ' + t.storeBinding,
      t.certificate ? when(t.certificate.expiresAt) : '—',
      t.lastRun ? el('span', null, statusBadge(t.lastRun.status), ' ', t.lastRun.errorCode ? el('span', { class: 'mono', text: t.lastRun.errorCode }) : '') : '—',
    ]);
    show(
      el('h1', { text: 'Targets' }),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), link('#/targets/new', 'New target', 'button')),
      table(['FQDN', 'State', 'Owner', 'Policy', 'Execution / DNS / Store', 'Certificate expires', 'Last run'], rows),
    );
  }

  async function viewTarget(id) {
    setNav('targets');
    const [t, runs] = await Promise.all([api('GET', '/targets/' + encodeURIComponent(id)), api('GET', '/targets/' + encodeURIComponent(id) + '/runs?limit=50')]);
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
    show(
      el('h1', null, el('span', { class: 'mono', text: t.fqdn }), ' ', enabledBadge(t.enabled)),
      status,
      el('div', { class: 'toolbar' },
        act('Request run now', 'POST', '/targets/' + encodeURIComponent(t.id) + '/runs', 'primary', { revision: t.revision }),
        t.enabled ? act('Disable', 'POST', '/targets/' + encodeURIComponent(t.id) + '/disable', 'danger') : act('Enable', 'POST', '/targets/' + encodeURIComponent(t.id) + '/enable'),
      ),
      props([
        ['Id', el('span', { class: 'mono', text: t.id })],
        ['Owner', t.owner],
        ['Policy', link('#/policies/' + encodeURIComponent(t.policyRef), t.policyRef, 'mono')],
        ['Execution binding', t.executionBinding],
        ['DNS binding', t.dnsBinding],
        ['Store binding', t.storeBinding],
        ['Revision', String(t.revision)],
        ['Created / updated', when(t.createdAt) + ' / ' + when(t.updatedAt)],
        ['Certificate', cert ? el('span', null, 'expires ' + when(cert.expiresAt) + ', stored as ', el('span', { class: 'mono', text: cert.storeObjectRef }), ', fingerprint ', el('span', { class: 'mono', text: cert.fingerprintSha256 })) : 'none recorded'],
        ['Last successful run', cert ? link('#/runs/' + encodeURIComponent(cert.lastSucceededRunId), cert.lastSucceededRunId, 'mono') : '—'],
      ]),
      el('h2', { text: 'Edit' }),
      await targetForm(t),
      el('h2', { text: 'Runs' }),
      runsTable(runs.items, false),
    );
  }

  async function targetForm(t) {
    const b = await bindings();
    const policies = (await api('GET', '/policies')).items.map((p) => p.id);
    const isNew = !t;
    const fqdn = input('text', t ? t.fqdn : '', { placeholder: 'host.example.ac.jp', required: true, disabled: !isNew });
    const owner = input('text', t ? t.owner : '', { required: true, maxlength: 128 });
    const policy = select(policies, t ? t.policyRef : policies[0]);
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
              fqdn: fqdn.value.trim(), owner: owner.value, policyRef: policy.value,
              executionBinding: exec.value, dnsBinding: dns.value, storeBinding: store.value, enabled: enabled.checked,
            });
            location.hash = '#/targets/' + encodeURIComponent(created.id);
          } else {
            await api('PUT', '/targets/' + encodeURIComponent(t.id), {
              revision: t.revision, owner: owner.value, policyRef: policy.value,
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
    field('FQDN', fqdn, isNew ? 'One host name, ASCII, no trailing dot; a wildcard needs a policy that allows it.' : 'A target is one FQDN; create a new target to manage another name.'),
    field('Owner', owner, 'Who to contact about this certificate.'),
    field('Policy', policy),
    field('Execution binding', exec),
    field('DNS binding', dns),
    field('Store binding', store),
    field('Enabled', enabled),
    el('div', { class: 'actions' }, el('button', { class: 'primary', type: 'submit' }, isNew ? 'Create target' : 'Save changes')),
    );
    if (policies.length === 0) form.prepend(notice('error', 'Create a policy first.'));
    return form;
  }

  async function viewNewTarget() {
    setNav('targets');
    show(el('h1', { text: 'New target' }), await targetForm(null));
  }

  // Policies

  async function viewPolicies() {
    setNav('policies');
    const res = await api('GET', '/policies');
    const rows = res.items.map((p) => [
      td(link('#/policies/' + encodeURIComponent(p.id), p.id), 'mono'),
      enabledBadge(p.enabled),
      td(p.allowedDnsSuffixes.join(', '), 'mono'),
      p.allowWildcard ? 'yes' : 'no',
      p.acmeBinding,
      String(p.renewBeforeDays) + ' days',
      p.keyType,
    ]);
    show(
      el('h1', { text: 'Certificate policies' }),
      el('div', { class: 'toolbar' }, el('span', { class: 'spacer' }), link('#/policies/new', 'New policy', 'button')),
      table(['Id', 'State', 'Allowed suffixes', 'Wildcard', 'ACME binding', 'Renew before', 'Key'], rows),
    );
  }

  async function policyForm(p) {
    const b = await bindings();
    const isNew = !p;
    const suffixes = el('textarea', { rows: 3, placeholder: 'example.ac.jp\nlab.example.ac.jp' });
    suffixes.value = p ? p.allowedDnsSuffixes.join('\n') : '';
    const wildcard = checkbox(p ? p.allowWildcard : false);
    const acme = select(b.acme, p ? p.acmeBinding : b.acme[0]);
    const renew = input('number', p ? p.renewBeforeDays : 30, { min: 1, max: 365 });
    const keyType = select(['ec256', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'], p ? p.keyType : 'ec256');
    const enabled = checkbox(p ? p.enabled : true);
    const status = el('div');
    const body = () => ({
      allowedDnsSuffixes: suffixes.value.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s),
      allowWildcard: wildcard.checked,
      acmeBinding: acme.value,
      renewBeforeDays: Number(renew.value),
      keyType: keyType.value,
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
    field('Allowed DNS suffixes', suffixes, 'One per line. A target FQDN must be the suffix itself or end in ".<suffix>" (label boundary).'),
    field('Allow wildcard', wildcard),
    field('ACME binding', acme),
    field('Renew before (days)', renew),
    field('Key type', keyType),
    field('Enabled', enabled),
    el('div', { class: 'actions' }, el('button', { class: 'primary', type: 'submit' }, isNew ? 'Create policy' : 'Save changes')),
    );
  }

  async function viewPolicy(id) {
    setNav('policies');
    const [p, targets] = await Promise.all([api('GET', '/policies/' + encodeURIComponent(id)), api('GET', '/targets?policyRef=' + encodeURIComponent(id))]);
    show(
      el('h1', null, el('span', { class: 'mono', text: p.id }), ' ', enabledBadge(p.enabled)),
      props([
        ['Created / updated', when(p.createdAt) + ' / ' + when(p.updatedAt)],
        ['Max SANs', String(p.maxSANs)],
        ['Targets under this policy', String(targets.items.length)],
      ]),
      el('h2', { text: 'Edit' }),
      notice('', 'A change is refused if any target under the policy would no longer satisfy it.'),
      await policyForm(p),
      el('h2', { text: 'Targets' }),
      table(['FQDN', 'State', 'Owner'], targets.items.map((t) => [td(link('#/targets/' + encodeURIComponent(t.id), t.fqdn), 'mono'), enabledBadge(t.enabled), t.owner])),
    );
  }

  async function viewNewPolicy() {
    setNav('policies');
    show(el('h1', { text: 'New policy' }), await policyForm(null));
  }

  // Runs

  function runsTable(items, withTarget) {
    const headers = ['Run', 'Status', 'Requested', 'Finished', 'Action', 'Error', 'Requested by'];
    if (withTarget) headers.splice(1, 0, 'Target');
    return table(headers, items.map((r) => {
      const cells = [
        td(link('#/runs/' + encodeURIComponent(r.id), r.id), 'mono'),
        statusBadge(r.status),
        when(r.requestedAt),
        when(r.finishedAt),
        r.action || '—',
        r.error ? el('span', null, el('span', { class: 'mono', text: r.error.code }), ' ', r.error.summary) : '—',
        r.requestedBy,
      ];
      if (withTarget) cells.splice(1, 0, td(link('#/targets/' + encodeURIComponent(r.targetId), r.targetId), 'mono'));
      return cells;
    }));
  }

  async function viewRuns() {
    setNav('runs');
    const filter = new URLSearchParams(location.hash.split('?')[1] || '');
    const status = filter.get('status') || '';
    const res = await api('GET', '/runs?limit=100' + (status ? '&status=' + encodeURIComponent(status) : ''));
    const sel = select(['', 'queued', 'starting', 'running', 'succeeded', 'failed', 'cancelled'], status);
    sel.addEventListener('change', () => { location.hash = '#/runs' + (sel.value ? '?status=' + sel.value : ''); });
    show(
      el('h1', { text: 'Runs' }),
      el('div', { class: 'toolbar' }, el('label', { text: 'Status ' }), sel),
      runsTable(res.items, true),
    );
  }

  async function viewRun(id) {
    setNav('runs');
    const r = await api('GET', '/runs/' + encodeURIComponent(id));
    const status = el('div');
    const cancellable = ['queued', 'starting', 'running'].includes(r.status);
    show(
      el('h1', null, 'Run ', el('span', { class: 'mono', text: r.id }), ' ', statusBadge(r.status)),
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
      }, 'Cancel run') : null),
      props([
        ['Target', link('#/targets/' + encodeURIComponent(r.targetId), r.targetId, 'mono')],
        ['Target revision', String(r.targetRevision)],
        ['Requested by', el('span', null, el('span', { class: 'mono', text: r.requestedBy }), r.requestedByAuthority ? ' @ ' : '', r.requestedByAuthority ? el('span', { class: 'mono', text: r.requestedByAuthority }) : '')],
        ['Requested / started / finished', when(r.requestedAt) + ' / ' + when(r.startedAt) + ' / ' + when(r.finishedAt)],
        ['Action', r.action],
        ['Certificate expires', r.expiresAt ? when(r.expiresAt) : undefined],
        ['Fingerprint', r.fingerprintSha256 ? el('span', { class: 'mono', text: r.fingerprintSha256 }) : undefined],
        ['Store object', r.storeObjectRef ? el('span', { class: 'mono', text: r.storeObjectRef }) : undefined],
        ['Error', r.error ? el('span', null, el('span', { class: 'mono', text: r.error.code }), ' ', r.error.summary) : undefined],
        ['Execution', r.externalExecutionId ? el('span', { class: 'mono', text: r.externalExecutionId }) : undefined],
      ]),
    );
  }

  // Audit

  async function viewAudit() {
    setNav('audit');
    const res = await api('GET', '/audit?limit=200');
    show(
      el('h1', { text: 'Audit log' }),
      table(['Time', 'Actor', 'Authority', 'Action', 'Target', 'Run', 'Policy', 'Detail'], res.items.map((e) => [
        when(e.time),
        td(e.actor, 'mono'),
        e.actorAuthority ? td(e.actorAuthority, 'mono') : '—',
        td(e.action, 'mono'),
        e.targetId ? td(link('#/targets/' + encodeURIComponent(e.targetId), e.targetId), 'mono') : '—',
        e.runId ? td(link('#/runs/' + encodeURIComponent(e.runId), e.runId), 'mono') : '—',
        e.policyId ? td(link('#/policies/' + encodeURIComponent(e.policyId), e.policyId), 'mono') : '—',
        e.detail,
      ])),
    );
  }

  // Migration (docs/migration.md): the target source flag and, in shadow
  // mode, the latest comparison of the infrastructure list with the
  // registry. Read-only: importing is done with `acme-conductor migrate`.

  function reportTable(rep) {
    const rows = [];
    const push = (kind, e, note) => rows.push([statusBadge(kind), td(e.fqdn, 'mono'), e.targetId ? td(link('#/targets/' + encodeURIComponent(e.targetId), e.targetId), 'mono') : '—', note || '—']);
    for (const e of rep.added) push('added', e, 'not in the registry: an import would create it');
    for (const e of rep.changed) push('changed', e, (e.differences || []).map((d) => d.field + ': ' + d.registry + ' (expected ' + d.expected + ')').join('; '));
    for (const e of rep.missing) push('missing', e, 'not in the list' + (e.enabled === false ? ' (disabled)' : ''));
    for (const e of rep.rejected) push('rejected', e, e.reason);
    for (const e of rep.unchanged) push('unchanged', e, '');
    return table(['Category', 'FQDN', 'Target', 'Note'], rows);
  }

  async function viewMigration() {
    setNav('migration');
    const m = await api('GET', '/migration');
    const src = m.source ? (m.source.kind === 'inline' ? 'inline list (' + m.source.count + ' entries)' : m.source.kind + ' ' + m.source.path + (m.source.parameter ? ' (param ' + m.source.parameter + ')' : '')) : '—';
    const prof = m.profile ? m.profile.policyRef + ' / ' + m.profile.executionBinding + ' / ' + m.profile.dnsBinding + ' / ' + m.profile.storeBinding + ' / ' + m.profile.owner : '—';
    const parts = [
      el('h1', { text: 'Migration' }),
      m.issuanceEnabled ? null : notice('ok', 'Issuance is disabled: the Conductor plans and starts no runs while the target source is "' + m.targetSource + '".'),
      props([
        ['Target source', statusBadge(m.targetSource)],
        ['Issuance', m.issuanceEnabled ? 'enabled' : 'disabled'],
        ['Configured list', src],
        ['Import profile (policy / execution / dns / store / owner)', prof],
      ]),
    ];
    const lc = m.lastComparison;
    if (lc) {
      parts.push(el('h2', { text: 'Shadow comparison' }));
      if (lc.error) parts.push(notice('error', 'The latest comparison (' + when(lc.attemptedAt) + ') failed: ' + lc.error));
      if (lc.report) {
        const s = lc.report.summary;
        parts.push(props([
          ['Compared', when(lc.report.comparedAt)],
          ['Source', lc.report.source],
          ['Summary', 'added ' + s.added + ', changed ' + s.changed + ', missing ' + s.missing + ', unchanged ' + s.unchanged + ', rejected ' + s.rejected],
        ]), reportTable(lc.report));
      }
    } else if (m.targetSource === 'shadow') {
      parts.push(el('p', { class: 'empty', text: 'No comparison has been made yet.' }));
    }
    show(...parts);
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

  function nextGeneration(b) {
    return b.generations.length ? b.generations[0].generation + 1 : 1;
  }

  function provisioningForm(keyInfo, b, onDone) {
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
          const generation = nextGeneration(b);
          const encryptedCredential = await acmeConductorSealEAB(keyInfo, b.name, generation, k, h);
          clearInputs();
          await api('POST', '/acme-bindings/' + encodeURIComponent(b.name) + '/provisioning', { accountGeneration: generation, encryptedCredential });
          onDone();
        } catch (err) {
          clearInputs();
          status.append(notice('error', describe(err)));
        }
      },
    },
    status,
    el('p', { class: 'hint', text: 'Sealed in this browser to Runner key ' + keyInfo.keyId + ' before it is sent; the Conductor never sees the key id or HMAC.' }),
    field('EAB key id (kid)', kid),
    field('EAB HMAC key', hmac, 'Never displayed once submitted.'),
    el('div', { class: 'actions' }, el('button', { class: 'primary', type: 'submit' }, 'Provision / replace EAB (generation ' + nextGeneration(b) + ')')),
    );
  }

  function acmeBindingPanel(keyInfo, b, x25519Ok, refresh) {
    const parts = [
      el('h2', { text: b.name }),
      props([
        ['Active generation', b.activeGeneration || '—'],
        ['Pending', b.pending ? b.pending.generation + ' (' + b.pending.status + (b.pending.runId ? ', attached to run ' + b.pending.runId : '') + ')' : '—'],
      ]),
      table(['Generation', 'Status', 'Key id', 'Requested by', 'Created', 'Activated'],
        b.generations.map((g) => [g.generation, statusBadge(g.status), td(g.keyId, 'mono'), g.requestedBy, when(g.createdAt), when(g.activatedAt)])),
    ];
    if (b.pending && !b.pending.runId) {
      parts.push(el('div', { class: 'actions' }, el('button', {
        class: 'danger',
        onclick: async () => {
          try {
            await api('DELETE', '/acme-bindings/' + encodeURIComponent(b.name) + '/provisioning/' + encodeURIComponent(b.pending.generation));
            refresh();
          } catch (err) {
            parts.push(notice('error', describe(err)));
          }
        },
      }, 'Cancel pending provisioning (generation ' + b.pending.generation + ')')));
    }
    if (!b.externalAccountBinding) {
      parts.push(el('p', { class: 'hint', text: 'This binding is no longer listed in accountProvisioning.bindings: the pending generation is never sent to the Runner. Cancel it.' }));
    } else if (b.pending) {
      parts.push(el('p', { class: 'hint', text: 'A generation is already pending; cancel it before provisioning a new one.' }));
    } else if (!x25519Ok) {
      parts.push(notice('error', 'This browser has no WebCrypto X25519 support; account provisioning needs a browser that does.'));
    } else {
      parts.push(el('h3', { text: 'Provision / replace EAB' }), provisioningForm(keyInfo, b, refresh));
    }
    return el('div', { class: 'panel' }, ...parts);
  }

  // The page lists the bindings whose CA takes an EAB, plus any other
  // binding still holding a pending request (left from before it was
  // dropped from accountProvisioning.bindings) so that it can be
  // cancelled. A binding whose CA takes no EAB has nothing to show here.
  async function viewEAB() {
    setNav('eab');
    const keyInfo = await provisioningKey();
    const heading = el('h1', { text: 'External Account Binding' });
    if (!keyInfo) {
      show(heading, notice('error', 'Account provisioning is not configured on this Conductor.'));
      return;
    }
    const [res, x25519Ok] = await Promise.all([api('GET', '/acme-bindings'), acmeConductorX25519Supported()]);
    const items = res.items.filter((b) => b.externalAccountBinding || b.pending);
    const refresh = () => withErrors(() => viewEAB());
    show(
      heading,
      el('p', { class: 'notice', text: 'EAB credentials are sealed in this browser and never displayed once submitted.' }),
      ...(items.length
        ? items.map((b) => acmeBindingPanel(keyInfo, b, x25519Ok, refresh))
        : [el('p', { class: 'hint', text: 'No ACME binding is listed in accountProvisioning.bindings.' })]),
    );
  }

  // ---- routing --------------------------------------------------------------

  const routes = [
    [/^#\/targets\/new$/, () => viewNewTarget()],
    [/^#\/targets\/([A-Za-z0-9_-]+)$/, (m) => viewTarget(m[1])],
    [/^#\/targets$/, () => viewTargets()],
    [/^#\/policies\/new$/, () => viewNewPolicy()],
    [/^#\/policies\/([A-Za-z0-9_-]+)$/, (m) => viewPolicy(m[1])],
    [/^#\/policies$/, () => viewPolicies()],
    [/^#\/runs\/([A-Za-z0-9_-]+)$/, (m) => viewRun(m[1])],
    [/^#\/runs(\?.*)?$/, () => viewRuns()],
    [/^#\/audit$/, () => viewAudit()],
    [/^#\/migration$/, () => viewMigration()],
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

  async function start() {
    try {
      const res = await fetch('/ui/config', { headers: { Accept: 'application/json' }, credentials: 'omit' });
      if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => null));
      state.config = await res.json();
    } catch (err) {
      show(notice('error', 'The interface configuration could not be loaded: ' + describe(err)));
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

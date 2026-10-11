'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
const fixture = () => ({ revision: 7, slots: [{ id: 'slot-1', name: 'Exit A', enabled: true, scheme: 'http', host: 'proxy.test', port: 8080, username: 'user', has_password: true, transport_generation: 3, binding_count: 1, probe: { ip: '203.0.113.8', status: 'ok', generation: 3, latency_ms: 12, probed_at: new Date().toISOString() } }], accounts: { alice: { assigned: true, slot_id: 'slot-1', orphan: false, route: { state: 'ready' } }, bob: { assigned: false, slot_id: '', orphan: false, route: { state: 'direct' } }, gone: { assigned: true, slot_id: 'slot-1', orphan: true, route: { state: 'disabled' } } } });
test('current generation HTTP IP success and CONNECT 400 remain partial, not stale or HTTPS success', () => {
  const h = harness(), slot = fixture().slots[0];
  Object.assign(slot.probe, { status: 'error', ip_status: 'ok', ip_checked_at: slot.probe.probed_at, https_status: 'error', error_code: 'proxy_connect_failed', error_stage: 'connect', error_reason: 'connect_rejected', proxy_status: 400 });
  const html = h.ctx.proxyProbeHTML(slot);
  assert.match(html, /203\.0\.113\.8/);
  assert.match(html, /HTTP 观测/);
  assert.match(html, /HTTPS 检测/);
  assert.match(html, /CONNECT 400/);
  assert.match(html, /代理拒绝隧道/);
  assert.match(html, /不会单独阻止账号请求/);
  assert.doesNotMatch(html, /出站仍停止/);
  assert.match(html, /proxy_connect_failed/);
  assert.doesNotMatch(html, /已过期|代际已变/);
});
test('failed probe is a route warning rather than business-unavailable status', async () => {
  const h = harness(), data = fixture();
  Object.assign(data.slots[0].probe, { status: 'error', ip_status: 'ok', https_status: 'error', proxy_status: 400 });
  h.setData(data); await h.ctx.loadProxies();
  let html = h.ctx.accountRouteHTML('alice');
  assert.match(html, /检测异常/);
  assert.doesNotMatch(html, /代理不可用|代理就绪|代理连接失败/);
  data.accounts.alice.route.state = 'unavailable';
  h.setData(data); await h.ctx.loadProxies();
  html = h.ctx.accountRouteHTML('alice');
  assert.match(html, /代理故障冷却/);
  assert.doesNotMatch(html, /检测异常/);
  data.accounts.alice.route.state = 'ready';
  data.slots[0].probe.generation--;
  h.setData(data); await h.ctx.loadProxies();
  assert.doesNotMatch(h.ctx.accountRouteHTML('alice'), /检测异常/);
});
test('temporary proxy fault displays bounded recovery without requiring a manual probe', async () => {
  const h = harness(), data = fixture();
  Object.assign(data.accounts.alice.route, { state: 'unavailable', retry_after: 15 });
  h.setData(data); await h.ctx.loadProxies();
  const html = h.ctx.accountRouteHTML('alice');
  assert.match(html, /代理故障冷却/);
  assert.match(html, /后可重试/);
  assert.match(html, /无需手动检测解锁/);
  assert.match(html, /新请求仍尝试原代理/);
  assert.doesNotMatch(html, /代理就绪/);
});
test('same-generation failed first probe is failure only, not old generation or expired success', () => {
  const h = harness(), slot = fixture().slots[0];
  Object.assign(slot.probe, { status: 'error', ip: '', ip_status: 'error', https_status: 'error', error_code: 'proxy_timeout', error_stage: 'connect' });
  const html = h.ctx.proxyProbeHTML(slot);
  assert.match(html, /失败/);
  assert.match(html, /尚无/);
  assert.doesNotMatch(html, /已过期|代际已变/);
});
test('age and transport-generation messages are independent of latest failure', () => {
  const h = harness(), slot = fixture().slots[0];
  slot.probe.last_success_at = new Date(Date.now() - 16 * 60 * 1000).toISOString();
  let html = h.ctx.proxyProbeHTML(slot);
  assert.match(html, /成功结果已过期/);
  assert.doesNotMatch(html, /代际已变/);
  slot.probe.last_success_at = slot.probe.probed_at;
  slot.probe.generation--;
  html = h.ctx.proxyProbeHTML(slot);
  assert.match(html, /代际已变/);
  assert.doesNotMatch(html, /已过期/);
});
test('HTTPS-only success and legacy success stay readable without claiming HTTP observation', () => {
  const h = harness(), slot = fixture().slots[0];
  Object.assign(slot.probe, { ip_status: 'ok', https_status: 'ok' });
  const html = h.ctx.proxyProbeHTML(slot);
  assert.match(html, /HTTPS 检测/);
  assert.match(html, /通过/);
  assert.doesNotMatch(html, /HTTP 观测|出站仍停止/);
  delete slot.probe.ip_status;
  delete slot.probe.https_status;
  assert.match(h.ctx.proxyProbeHTML(slot), /通过/);
});
test('safe diagnostic reasons distinguish authentication, SOCKS handshake, and response checks', () => {
  const h = harness(), slot = fixture().slots[0];
  Object.assign(slot.probe, { status: 'error', ip: '', https_status: 'error', error_code: 'proxy_auth_failed', error_stage: 'connect', error_reason: 'authentication_rejected', proxy_status: 407 });
  assert.match(h.ctx.proxyProbeHTML(slot), /CONNECT 407.*代理认证失败/);
  Object.assign(slot.probe, { error_stage: 'socks_handshake', error_reason: 'socks_connect_rejected', proxy_status: 0 });
  assert.match(h.ctx.proxyProbeHTML(slot), /SOCKS 握手.*SOCKS 拒绝连接/);
  Object.assign(slot.probe, { error_stage: 'probe_ip', error_reason: '<secret>', proxy_status: '<secret>' });
  const html = h.ctx.proxyProbeHTML(slot);
  assert.match(html, /出口 IP 响应/);
  assert.doesNotMatch(html, /secret/);
});
test('SOCKS options retain selected protocol and password write-only behavior', async () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(html, /value="socks5"/);
  assert.match(html, /value="socks5h"/);
  assert.match(html, /代理端 DNS/);
  assert.match(html, /255 字节/);
  for (const scheme of ['socks5', 'socks5h']) {
    const h = harness(), data = fixture();
    data.slots[0].scheme = scheme;
    h.setData(data); await h.ctx.loadProxies(); h.ctx.openProxyEditor('slot-1');
    assert.equal(h.form.elements.scheme.value, scheme);
    assert.equal(h.form.elements.password.value, '');
    await h.ctx.saveProxyEditor({ preventDefault() {} });
    const patch = h.calls.find(c => c.method === 'PATCH');
    assert.equal(patch.body.scheme, scheme);
    assert.equal('password' in patch.body, false);
    assert.deepEqual(h.storage, []);
  }
});
test('failed probe retains last successful IP and time, marked stale separately from latest attempt', () => {
  const h=harness(),slot=fixture().slots[0];
  slot.probe.status='error';slot.probe.error_code='proxy_connect_failed';
  slot.probe.last_success_at='2026-10-10T08:00:00Z';
  const html=h.ctx.proxyProbeHTML(slot);
  assert.match(html,/203\.0\.113\.8/);assert.match(html,/proxy_connect_failed/);
  assert.match(html,/上次成功/);assert.match(html,/最近尝试/);assert.match(html,/已过期/);
});
function harness() {
  const elements = new Map(), timers = new Map(), calls = [], confirms = [], storage = [];
  let nextTimer = 0;
  function element(id) {
    if (elements.has(id)) return elements.get(id);
    const el = { id, value: '', innerHTML: '', textContent: '', hidden: false, disabled: false, checked: false, dataset: {}, children: [], listeners: {}, style: {},
      classList: { add() {}, remove() {}, toggle() {} }, addEventListener(type, fn) { this.listeners[type] = fn; }, focus() {}, appendChild() {}, remove() {}, querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; }, setAttribute() {}, getAttribute() { return null; } };
    elements.set(id, el); return el;
  }
  const form = element('proxyForm');
  form.elements = Object.fromEntries(['name', 'host', 'port', 'scheme', 'username', 'password', 'clear_password', 'enabled'].map(k => [k, element('field-' + k)]));
  const selects = [];
  let data = fixture();
  const ctx = {
    console, JSON, Math, Date, Number, String, Boolean, Object, Array, Promise, Map, Set, RegExp, Error, TypeError, isNaN, parseInt, parseFloat, encodeURIComponent, decodeURIComponent, URL, URLSearchParams,
    location: { hash: '#proxies' }, history: { replaceState() {} }, navigator: { clipboard: { writeText: async () => {} } },
    localStorage: { getItem: () => null, setItem: (...args) => storage.push(args) },
    document: { getElementById: element, documentElement: element('document'), activeElement: null, querySelectorAll: selector => selector === '[data-proxy-uid]' ? selects : [], querySelector: () => ({ value: 'global' }), createElement: () => element('toast'), addEventListener() {} },
    addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }),
    setTimeout: (fn, delay) => { timers.set(++nextTimer, { fn, delay }); return nextTimer; }, clearTimeout: id => timers.delete(id), setInterval: () => ++nextTimer, clearInterval() {},
    fetch: () => new Promise(() => {}), confirm: message => { confirms.push(message); return true; }, open() {},
    fakeAPI: async (route, opts) => { calls.push({ route, method: opts?.method || 'GET', body: opts?.body ? JSON.parse(opts.body) : null }); if (route === 'proxies') return clone(data); return { ok: true }; },
  };
  ctx.window = ctx; ctx.globalThis = ctx;
  vm.createContext(ctx); vm.runInContext(source, ctx);
  vm.runInContext('api = fakeAPI; proxyLoading = false; loadOverview = async () => {};', ctx);
  return { ctx, el: element, form, calls, confirms, storage, timers, selects, eval: text => vm.runInContext(text, ctx), setData(value) { data = value; }, api(fn) { ctx.fakeAPI = fn; vm.runInContext('api = fakeAPI', ctx); } };
}

test('slot editing survives 5s refresh and password is write-only, including HTML/localStorage', async () => {
  const h = harness(); await h.ctx.loadProxies(); h.ctx.openProxyEditor('slot-1');
  assert.equal(h.form.elements.password.value, '');
  h.form.elements.name.value = 'Unsaved'; h.form.elements.password.value = 'new-secret';
  h.form.listeners.input();
  const newer = fixture(); newer.revision = 8; newer.slots[0].name = 'Remote edit'; h.setData(newer);
  await h.ctx.refreshVisible(); await h.ctx.loadProxies();
  assert.equal(h.form.elements.name.value, 'Unsaved'); assert.equal(h.form.elements.password.value, 'new-secret');
  assert.equal(h.eval('proxyEditor.revision'), 7);
  assert.equal(h.el('proxySlots').innerHTML.includes('new-secret'), false);
  assert.deepEqual(h.storage, []);
  h.ctx.closeProxyEditor(true); assert.equal(h.form.elements.password.value, '');
});

test('create and edit use frozen revision, omit unchanged password, explicitly clear password', async () => {
  const h = harness(); await h.ctx.loadProxies(); h.ctx.openProxyEditor('');
  h.form.elements.name.value = 'New'; h.form.elements.host.value = 'new.test';
  await h.ctx.saveProxyEditor({ preventDefault() {} });
  const created = h.calls.find(c => c.method === 'POST');
  assert.equal(created.route, 'proxies'); assert.equal(created.body.revision, 7); assert.ok(created.body.operation_id); assert.equal('password' in created.body, false);
  h.ctx.openProxyEditor('slot-1'); h.form.elements.clear_password.checked = true;
  await h.ctx.saveProxyEditor({ preventDefault() {} });
  const patch = h.calls.find(c => c.method === 'PATCH'); assert.equal(patch.body.clear_password, true); assert.equal('password' in patch.body, false);
});

test('slot enable/disable/delete/probe use exact management DTOs and confirmations', async () => {
  const h = harness(); await h.ctx.loadProxies();
  await h.ctx.proxySlotAction('toggle', 'slot-1'); await h.ctx.proxySlotAction('probe', 'slot-1'); await h.ctx.proxySlotAction('delete', 'slot-1');
  assert.equal(h.calls.find(c => c.method === 'PATCH').body.enabled, false);
  assert.deepEqual(h.calls.find(c => c.route.endsWith('/test')).body, { generation: 3 });
  assert.deepEqual(h.calls.find(c => c.method === 'DELETE').body, { revision: 7 });
  assert.equal(h.confirms.length, 2);
});

test('dirty binding controls survive refresh; explicit direct requires confirmation and preserves old CAS revision', async () => {
  const h = harness(); await h.ctx.loadProxies();
  const select = h.el('alice-select'); select.dataset.proxyUid = 'alice'; select.value = ''; h.selects.push(select);
  h.el('proxyBindings').listeners.change({ target: select });
  h.el('proxyBindings').innerHTML = 'edited controls';
  const newer = fixture(); newer.revision = 9; h.setData(newer); await h.ctx.loadProxies();
  assert.equal(h.el('proxyBindings').innerHTML, 'edited controls');
  await h.ctx.saveProxyBinding('alice');
  const put = h.calls.find(c => c.method === 'PUT'); assert.deepEqual(put.body, { revision: 7, slot_id: '' }); assert.match(h.confirms[0], /显式设为直连/);
});

test('orphan binding cleanup is explicit and never sent for polling', async () => {
  const h = harness(); await h.ctx.loadProxies(); assert.equal(h.calls.some(c => c.method === 'DELETE'), false);
  await h.ctx.cleanProxyOrphan('gone');
  assert.deepEqual(h.calls.find(c => c.method === 'DELETE').body, { revision: 7, confirm: true });
  assert.match(h.confirms[0], /孤儿绑定/);
});

test('batch preview freezes assignments/revision and confirms exact preview; conflict requires re-preview', async () => {
  const h = harness(); await h.ctx.loadProxies(); h.el('proxyBatchRealm').value = 'global'; h.el('proxyBatchUIDs').value = 'bob';
  h.api(async (route, opts) => {
    const body = opts?.body ? JSON.parse(opts.body) : null; h.calls.push({ route, body });
    if (route === 'proxies') return fixture();
    if (body.preview) return { revision: 7, assignments: { bob: 'slot-1' }, skipped: { alice: 'already_assigned' } };
    const e = new Error('revision_conflict'); e.code = 'revision_conflict'; e.status = 409; throw e;
  });
  await h.ctx.previewProxyBatch(); assert.equal(h.el('btnProxyBatchConfirm').disabled, false);
  await h.ctx.confirmProxyBatch();
  const confirm = h.calls.find(c => c.body && c.body.preview === false);
  assert.deepEqual(confirm.body.assignments, { bob: 'slot-1' }); assert.equal(confirm.body.expected_revision, 7); assert.ok(confirm.body.operation_id);
  assert.equal(h.eval('proxyBatch'), null); assert.equal(h.el('btnProxyBatchConfirm').disabled, true); assert.match(h.el('proxyBatchPreview').textContent, /重新预览/);
});

test('route status is separate from account penalty; probe shows IP/time/stale generation and escaped fields', async () => {
  const h = harness(); await h.ctx.loadProxies();
  assert.match(h.ctx.proxyRouteHTML({ assigned: true, slot_id: 'slot-1', route: { state: 'disabled' } }), /代理停用/);
  assert.doesNotMatch(h.ctx.proxyRouteHTML({ assigned: true, slot_id: 'slot-1', route: { state: 'disabled' } }), /账号禁用|账号失效/);
  const slot = fixture().slots[0]; slot.probe.generation = 2; slot.probe.ip = '<script>';
  assert.match(h.ctx.proxyProbeHTML(slot), /&lt;script&gt;/); assert.match(h.ctx.proxyProbeHTML(slot), /代际已变/); assert.match(h.ctx.proxyProbeHTML(slot), /12 ms/);
});

test('OAuth starts with selected server route, pending polls are single-flight, terminal stops and cancel releases', async () => {
  const h = harness(); h.el('addProxySlot').value = 'slot-1'; h.el('btnStartLogin').disabled = false;
  let resolvePoll; let polls = 0;
  h.api(async (route, opts) => {
    h.calls.push({ route, body: opts?.body ? JSON.parse(opts.body) : null });
    if (route === 'login/start') return { state: 'state-1', url: 'https://official.example/auth' };
    if (route.startsWith('login/poll')) { polls++; return new Promise(resolve => { resolvePoll = resolve; }); }
    return {};
  });
  await h.ctx.startAddLogin(); assert.deepEqual(h.calls[0].body, { realm: 'global', proxy_slot_id: 'slot-1' });
  const first = h.ctx.pollLogin(); await h.ctx.pollLogin(); assert.equal(polls, 1);
  resolvePoll({ done: false }); await first; assert.equal(h.eval('loginState'), 'state-1'); assert.ok(h.eval('loginTimer'));
  const terminal = h.ctx.pollLogin(); resolvePoll({ error: 'oauth_proxy_changed', code: 'oauth_proxy_changed' }); await terminal;
  assert.equal(h.eval('loginState'), null); assert.equal(h.eval('loginTimer'), null); assert.ok(h.calls.some(c => c.route === 'login/cancel'));
  assert.match(h.el('addErr').textContent, /代理槽已变化/);
});

test('OAuth late start after closing is canceled', async () => {
  const h = harness(); h.el('addProxySlot').value = 'slot-1';
  let startResolve; h.api(async (route, opts) => { h.calls.push({ route, body: opts?.body ? JSON.parse(opts.body) : null }); if (route === 'login/start') return new Promise(r => { startResolve = r; }); return {}; });
  const promise = h.ctx.startAddLogin(); h.ctx.closeAdd(); startResolve({ state: 'late-state', url: 'https://official.example/' }); await promise;
  assert.ok(h.calls.some(c => c.route === 'login/cancel' && c.body.state === 'late-state')); assert.equal(h.eval('loginState'), null);
});

test('OAuth existing binding requires explicit rebind confirmation then poll query, done is applied once', async () => {
  const h = harness(); h.el('addProxySlot').value = 'slot-1'; let count = 0;
  h.api(async (route, opts) => {
    h.calls.push({ route, body: opts?.body ? JSON.parse(opts.body) : null });
    if (route === 'login/start') return { state: 'existing', url: 'https://official.example/' };
    if (route === 'proxies') return fixture();
    if (route.startsWith('login/poll')) { count++; if (count === 1) { const e = new Error('oauth_rebind_required'); e.code = 'oauth_rebind_required'; e.status = 409; throw e; } return { done: true, uid: 'alice' }; }
    return {};
  });
  await h.ctx.startAddLogin(); await h.ctx.pollLogin(); assert.equal(h.eval('loginRebind'), true); assert.match(h.confirms[0], /改绑/);
  await h.ctx.pollLogin(); await h.ctx.pollLogin(); assert.equal(count, 2);
  assert.ok(h.calls.some(c => c.route.includes('confirm_rebind=true'))); assert.equal(h.eval('loginState'), null);
});

test('write errors retain dirty input and frozen revision without retrying or direct fallback', async () => {
  const h = harness(); await h.ctx.loadProxies(); h.ctx.openProxyEditor('slot-1'); h.form.elements.name.value = 'retain'; h.form.listeners.input();
  let requests = 0; h.api(async () => { requests++; const e = new Error('revision_conflict'); e.code = 'revision_conflict'; e.status = 409; throw e; });
  await h.ctx.saveProxyEditor({ preventDefault() {} });
  assert.equal(requests, 1); assert.equal(h.form.elements.name.value, 'retain'); assert.equal(h.eval('proxyEditor.revision'), 7); assert.match(h.el('proxyEditorError').textContent, /输入仍保留/);
});

test('declining direct or existing-account rebind sends no confirming write', async () => {
  const h = harness(); await h.ctx.loadProxies();
  const select = h.el('alice-select'); select.dataset.proxyUid = 'alice'; select.value = ''; h.selects.push(select);
  h.ctx.confirm = () => false;
  await h.ctx.saveProxyBinding('alice');
  assert.equal(h.calls.some(c => c.method === 'PUT'), false);
  h.el('addProxySlot').value = '';
  await h.ctx.startAddLogin();
  assert.equal(h.calls.some(c => c.route === 'login/start'), false);
});

test('successful batch confirms exact preview, preserves explicit direct and existing bindings', async () => {
  const h = harness(); await h.ctx.loadProxies();
  h.api(async (route, opts) => {
    const body = opts?.body ? JSON.parse(opts.body) : null; h.calls.push({ route, body });
    if (route === 'proxies') return fixture();
    return body.preview ? { revision: 7, assignments: { bob: 'slot-1' }, skipped: { alice: 'already_assigned' } } : { ok: true, revision: 8 };
  });
  await h.ctx.previewProxyBatch(); await h.ctx.confirmProxyBatch();
  const request = h.calls.find(c => c.body?.preview === false);
  assert.deepEqual(request.body.assignments, { bob: 'slot-1' });
  assert.equal(h.eval('proxyBatch'), null); assert.match(h.el('proxyBatchPreview').textContent, /已提交/);
});

test('disabled slot can be enabled, and canceled OAuth releases exactly the current state', async () => {
  const h = harness(); const data = fixture(); data.slots[0].enabled = false; h.setData(data); await h.ctx.loadProxies();
  await h.ctx.proxySlotAction('toggle', 'slot-1');
  assert.equal(h.calls.find(c => c.method === 'PATCH').body.enabled, true);
  h.eval("loginState = 'cancel-me'");
  h.ctx.closeAdd(); await Promise.resolve();
  assert.deepEqual(h.calls.find(c => c.route === 'login/cancel').body, { state: 'cancel-me' });
});

test('switching to import cancels a late OAuth start before exposing its link', async () => {
  const h = harness(); h.el('addProxySlot').value = 'slot-1';
  let resolveStart;
  h.api(async (route, opts) => {
    h.calls.push({ route, body: opts?.body ? JSON.parse(opts.body) : null });
    if (route === 'login/start') return new Promise(resolve => { resolveStart = resolve; });
    return {};
  });
  const start = h.ctx.startAddLogin(); h.ctx.switchAddTab('import');
  resolveStart({ state: 'tab-late', url: 'https://official.example/' }); await start;
  assert.equal(h.eval('loginState'), null);
  assert.ok(h.calls.some(c => c.route === 'login/cancel' && c.body.state === 'tab-late'));
});

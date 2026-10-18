'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const configCode = source.slice(source.indexOf('const CFG_MAP ='), source.indexOf('/* Go 时长字段即时校验'));

function harness() {
  const calls = [], elements = new Map();
  function element(id) {
    if (!elements.has(id)) {
      const el = { textContent: '', checked: false, type: 'checkbox', value: '', elements: {} };
      Object.defineProperty(el, 'innerHTML', { set() { throw new Error('diagnostics must never render HTML'); } });
      elements.set(id, el);
    }
    return elements.get(id);
  }
  element('cfgForm').elements.strict_cooldown = element('strict_cooldown');
  let diagnostics = { strict_cooldown: true, profiles: [], accounts: [], warnings: [] };
  let config = { pool: { strict_cooldown: true } };
  const ctx = {
    $: element, cfgLoaded: null, console, JSON, Object, Array, String, Number, Set,
    markDurationFields() {}, toast() {},
    api: async route => {
      calls.push(route);
      if (route === 'config') return { config, path: '/fixture/config.json' };
      if (route === 'protocol_diagnostics') return diagnostics;
      throw new Error('unexpected API route');
    },
  };
  vm.createContext(ctx);
  vm.runInContext(configCode, ctx);
  return { ctx, calls, element, setDiagnostics(d) { diagnostics = d; }, setConfig(c) { config = c; } };
}

test('protocol diagnostics renders attacker-controlled fields only as text', async () => {
  const h = harness(), xss = '<img src=x onerror=alert(1)>';
  h.setDiagnostics({
    strict_cooldown: true, task_reporting: 'unchanged',
    profiles: [{ realm: xss, user_agent: xss, client_version: xss, cli_version: xss, client_name: xss, ua_override: true }],
    accounts: [{ uid: xss, realm: xss, device_token: { source: 'file', configured: true }, route: { state: xss, slot_id: xss, generation: 2 } }],
    warnings: ['shared_device_token_fallback_configured'],
  });
  await h.ctx.loadProtocolDiagnostics();
  const text = h.element('protocolDiagnostics').textContent;
  assert.match(text, /<img src=x onerror=alert\(1\)>/);
  assert.match(text, /未读取文件\/未确认存在/);
  assert.match(text, /可能共享/);
  assert.match(text, /任务上报及专用指纹：保持原样/);
  assert.match(text, /自定义 UA/);
  assert.deepEqual(h.calls, ['protocol_diagnostics']);
});

test('strict cooldown maps to pool config and submits explicit true and false', async () => {
  assert.match(html, /type="checkbox" name="strict_cooldown"/);
  assert.match(html, /id="btnProtocolDiagnostics"/);
  assert.match(html, /id="protocolDiagnostics"/);
  const h = harness();
  await h.ctx.loadConfig();
  assert.equal(h.element('strict_cooldown').checked, true);
  assert.equal(h.ctx.collectConfig().pool.strict_cooldown, true);
  h.element('strict_cooldown').checked = false;
  assert.equal(h.ctx.collectConfig().pool.strict_cooldown, false);
  h.setConfig({ pool: { strict_cooldown: false } });
  await h.ctx.loadConfig();
  assert.equal(h.element('strict_cooldown').checked, false);
  assert.equal(h.ctx.collectConfig().pool.strict_cooldown, false);
  assert.equal(h.calls.filter(r => r === 'protocol_diagnostics').length, 2);
});

test('manual refresh is on demand and failures are safe text without timers', async () => {
  const h = harness();
  assert.equal(h.calls.length, 0);
  assert.doesNotMatch(configCode, /setInterval|setTimeout/);
  await h.element('btnProtocolDiagnostics').onclick();
  assert.deepEqual(h.calls, ['protocol_diagnostics']);
  h.ctx.api = async () => { throw new Error('<svg onload=alert(1)>'); };
  await h.ctx.loadProtocolDiagnostics();
  assert.equal(h.element('protocolDiagnostics').textContent, '诊断暂不可用：<svg onload=alert(1)>');
  const start = source.indexOf('function refreshVisible()');
  assert.ok(start >= 0, 'periodic refresh function must be located');
  const refresh = source.slice(start, source.indexOf('function start()', start));
  assert.doesNotMatch(refresh, /loadProtocolDiagnostics/);
});

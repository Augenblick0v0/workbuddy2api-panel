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
    identities: [{ realm: xss, identity: xss, user_agent: xss, client_version: xss, cli_version: xss, ide_version: xss, origin: xss, language: xss, product: xss }],
    purpose_profiles: [{ realm: xss, purpose: xss, identity: xss, endpoint_origin: xss, user_agent: xss, origin: xss, referer: xss, language: xss, product: xss, client_version: xss, cli_version: xss, ide_version: xss, agent_intent: xss, agent_type: xss, agent_purpose: xss, private_data: true, machine_header: true, session_header: true }],
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
  // 身份矩阵渲染：三行 identities + 用途行带身份/版本/归属头，且一律纯文本。
  assert.match(text, /身份 \[/);
  assert.match(text, /用途 \[/);
  assert.match(text, /私标：发送/);
  assert.match(text, /机器\/会话头：有\/有/);
  assert.deepEqual(h.calls, ['protocol_diagnostics']);
});

test('identity matrix text exposes no device ids or credentials', () => {
  const h = harness();
  const text = h.ctx.protocolDiagnosticsText({
    strict_cooldown: true, task_reporting: 'unchanged',
    identities: [
      { realm: 'cn', identity: 'workbuddy-desktop', user_agent: 'WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1', client_version: '5.5.6', cli_version: '2.137.1', ide_version: '5.5.6', origin: 'https://www.codebuddy.cn', language: 'zh-CN', product: 'SaaS' },
      { realm: 'global', identity: 'workbuddy-desktop', user_agent: 'WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0', client_version: '5.8.4', cli_version: '2.161.0', ide_version: '5.8.4', origin: 'https://www.workbuddy.ai', language: 'en-US', product: 'SaaS' },
      { realm: 'cn', identity: 'workbuddy-mp', user_agent: '', client_version: '2.4.0', cli_version: '', ide_version: '2.4.0', origin: 'https://www.codebuddy.cn', language: 'zh-CN', product: 'SaaS' },
    ],
  });
  assert.match(text, /workbuddy-ai/);
  assert.match(text, /身份 \[cn\/workbuddy-mp\]/);
  assert.match(text, /不发送/);
  // 设备 ID / 凭据绝不出现在诊断页文本里。
  assert.doesNotMatch(text, /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}/);
  assert.doesNotMatch(text, /Bearer|authorization/i);
  assert.doesNotMatch(text, /0655736a/);
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

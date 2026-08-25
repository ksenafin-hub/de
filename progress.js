(function (global) {
  'use strict';

  const ROUNDS = 310000;
  const BASE = 'https://api.github.com';

  const cfg = { owner: null, repo: null, path: null, seed: null, delay: 20000 };
  let access = null, box = null;
  let items = {}, rev = null;
  let timer = null, busy = false, listeners = [];

  const LS_I = () => `dt:${cfg.path}:i`;
  const LS_S = 'dt:s';

  const emit = (t, p) => listeners.forEach(fn => { try { fn(t, p); } catch (e) {} });
  const enc64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const dec64 = s => Uint8Array.from(atob(s.replace(/\s/g, '')), c => c.charCodeAt(0));
  const readLS = (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } };
  const writeLS = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} };

  async function expand(phrase, salt) {
    const src = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(phrase), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: ROUNDS, hash: 'SHA-256' }, src, 512));
    return {
      a: await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['decrypt']),
      b: await crypto.subtle.importKey('raw', bits.slice(32, 64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
      raw: bits.slice(32, 64),
    };
  }

  async function pack(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const out0 = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
    const out = new Uint8Array(12 + out0.length);
    out.set(iv, 0); out.set(out0, 12);
    return enc64(out);
  }

  async function unpack(key, s) {
    const raw = dec64(s);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async function open(phrase) {
    const raw = dec64(cfg.seed);
    const k = await expand(phrase, raw.slice(0, 16));
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(16, 28) }, k.a, raw.slice(28));
    return { access: new TextDecoder().decode(plain), box: k.b, raw: k.raw };
  }

  function mergeInto(target, incoming) {
    for (const [id, item] of Object.entries(incoming || {})) {
      const cur = target[id];
      if (!cur || Number(item.ts || 0) > Number(cur.ts || 0)) target[id] = item;
    }
    return target;
  }

  const head = () => ({
    Authorization: 'Bearer ' + access,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  });

  const loc = () =>
    `${BASE}/repos/${cfg.owner}/${cfg.repo}/contents/${encodeURIComponent(cfg.path)}`;

  async function pull() {
    const res = await fetch(loc() + '?ref=main', { headers: head(), cache: 'no-store' });
    if (res.status === 404) { rev = null; return items; }
    if (res.status === 401 || res.status === 403) throw Object.assign(new Error('no'), { code: 'NO' });
    if (!res.ok) throw new Error('pull ' + res.status);
    const body = await res.json();
    rev = body.sha;
    const stored = atob(body.content.replace(/\s/g, ''));
    if (stored) mergeInto(items, await unpack(box, stored));
    writeLS(LS_I(), items);
    return items;
  }

  async function push() {
    if (busy || !access) return;
    busy = true;
    try {
      for (let n = 0; n < 4; n++) {
        const payload = await pack(box, items);
        const res = await fetch(loc(), {
          method: 'PUT',
          headers: { ...head(), 'Content-Type': 'application/json' },
          body: JSON.stringify({
            message: 'progress ' + new Date().toISOString().slice(0, 16),
            content: btoa(payload),
            sha: rev || undefined,
            branch: 'main',
          }),
        });
        if (res.status === 409 || res.status === 422) { await pull(); continue; }
        if (!res.ok) throw new Error('push ' + res.status);
        rev = (await res.json()).content.sha;
        writeLS(LS_I(), items);
        emit('status', 'synced');
        return;
      }
      emit('status', 'conflict');
    } catch (e) {
      emit('status', 'offline');
    } finally { busy = false; }
  }

  function schedule() { clearTimeout(timer); timer = setTimeout(push, cfg.delay); }

  function ask(message) {
    return new Promise(resolve => {
      const w = document.createElement('div');
      w.setAttribute('role', 'dialog'); w.setAttribute('aria-modal', 'true');
      w.style.cssText = 'position:fixed;inset:0;z-index:9999;display:grid;place-items:center;background:#17242bcc;padding:16px';
      w.innerHTML =
        '<div style="background:#F3F5EF;border:1px solid #BAC2B7;max-width:380px;width:100%;padding:22px;font-family:system-ui,sans-serif;color:#17242B">' +
        '<div style="font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#5C6A66;margin-bottom:6px">Прогресс</div>' +
        '<h2 style="margin:0 0 4px;font-size:20px;font-weight:600">Введите пароль</h2>' +
        '<p style="margin:0 0 14px;font-size:13.5px;line-height:1.45;color:#5C6A66">' +
        (message || 'Один пароль на всех устройствах открывает один и тот же прогресс.') + '</p>' +
        '<input type="password" autocomplete="current-password" style="width:100%;box-sizing:border-box;font-size:16px;padding:9px 10px;border:1.5px solid #17242B;background:#fff;border-radius:0">' +
        '<label style="display:flex;gap:8px;align-items:center;margin:12px 0 16px;font-size:13px;color:#5C6A66"><input type="checkbox" checked style="width:auto;accent-color:#4E2E78">Запомнить на этом устройстве</label>' +
        '<div style="display:flex;gap:8px">' +
        '<button data-ok style="flex:1;font-size:13px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;padding:10px;background:#4E2E78;color:#fff;border:0;cursor:pointer">Открыть</button>' +
        '<button data-skip style="font-size:13px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;padding:10px 14px;background:transparent;border:1.5px solid #17242B;cursor:pointer">Локально</button>' +
        '</div></div>';
      const inp = w.querySelector('input[type=password]');
      const rem = w.querySelector('input[type=checkbox]');
      const done = v => { w.remove(); resolve(v); };
      w.querySelector('[data-ok]').onclick = () => inp.value && done({ phrase: inp.value, remember: rem.checked });
      w.querySelector('[data-skip]').onclick = () => done(null);
      inp.onkeydown = e => { if (e.key === 'Enter') w.querySelector('[data-ok]').click(); };
      document.body.appendChild(w); inp.focus();
    });
  }

  const Progress = {
    init(o) {
      Object.assign(cfg, o);
      items = readLS(LS_I(), {});
      global.addEventListener('online', push);
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') push();
      });
      return Progress;
    },

    async start(force) {
      const saved = !force && readLS(LS_S, null);
      if (saved) {
        access = saved.a;
        box = await crypto.subtle.importKey('raw', dec64(saved.b),
          { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
      } else {
        let msg;
        for (;;) {
          const r = await ask(msg);
          if (!r) return items;
          emit('status', 'opening');
          let opened;
          try { opened = await open(r.phrase); }
          catch (e) { msg = 'Пароль не подошёл. Попробуйте ещё раз.'; continue; }
          access = opened.access;
          box = opened.box;
          if (r.remember) writeLS(LS_S, { a: access, b: enc64(opened.raw) });
          break;
        }
      }
      try { await pull(); emit('status', 'synced'); }
      catch (e) { emit('status', e.code === 'NO' ? 'expired' : 'offline'); }
      return items;
    },

    touch(id, data) {
      items[id] = Object.assign({}, items[id], data, { ts: Date.now() });
      writeLS(LS_I(), items);
      schedule();
      return items[id];
    },

    get: id => items[id],
    all: () => items,
    flush: push,
    on(fn) { listeners.push(fn); return Progress; },

    forget() {
      try { localStorage.removeItem(LS_S); } catch (e) {}
      access = null; box = null;
    },
  };

  global.Progress = Progress;
})(window);

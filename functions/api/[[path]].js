// Cloudflare Pages Function — /api/*  (KV binding: DB, env: ADMIN_PASSWORD)
const J = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h } });
const enc = new TextEncoder();
const DEF = { announcements: [], posts: [], settings: { headline: '', showAnnouncements: true, showBoard: true } };

async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function same(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
const secret = env => env.SESSION_SECRET || env.ADMIN_PASSWORD;
async function isAdmin(req, env) {
  const m = (req.headers.get('Cookie') || '').match(/(?:^|; )cs=(\d+)\.([a-f0-9]+)/);
  if (!m || Date.now() > +m[1]) return false;
  return same(m[2], await hmac(secret(env), 'admin.' + m[1]));
}
async function load(env) { return { ...DEF, ...(JSON.parse((await env.DB.get('data')) || 'null') || {}) }; }
const save = (env, d) => env.DB.put('data', JSON.stringify(d));
const clip = (s, n) => String(s ?? '').trim().slice(0, n);
const today = () => new Date().toLocaleDateString('ko-KR', { timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit' });

export async function onRequest({ request, env, params }) {
  const path = '/' + (params.path || []).join('/');
  const method = request.method;
  if (!env.DB || !env.ADMIN_PASSWORD) return J({ error: '서버 설정(DB, ADMIN_PASSWORD)이 필요합니다.' }, 500);

  if (path === '/content' && method === 'GET') {
    const d = await load(env);
    return J({ announcements: d.announcements, posts: d.posts, settings: d.settings });
  }

  if (path === '/admin/login' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    const ok = same(await hmac('pw', String(b.password || '')), await hmac('pw', env.ADMIN_PASSWORD));
    if (!ok) { await new Promise(r => setTimeout(r, 800)); return J({ error: '비밀번호가 올바르지 않습니다.' }, 401); }
    const exp = Date.now() + 7 * 864e5;
    const tok = exp + '.' + await hmac(secret(env), 'admin.' + exp);
    return J({ ok: true }, 200, { 'Set-Cookie': `cs=${tok}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict` });
  }
  if (path === '/admin/logout' && method === 'POST')
    return J({ ok: true }, 200, { 'Set-Cookie': 'cs=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict' });

  if (path.startsWith('/admin')) {
    if (!(await isAdmin(request, env))) return J({ error: '로그인이 필요합니다.' }, 401);
    if (path === '/admin/me') return J({ ok: true });
    const d = await load(env);
    if (path === '/admin/content' && method === 'GET') return J(d);

    if (path === '/admin/settings' && method === 'PUT') {
      const b = await request.json().catch(() => ({}));
      d.settings = { headline: clip(b.headline, 120), showAnnouncements: b.showAnnouncements !== false, showBoard: b.showBoard !== false };
      await save(env, d); return J({ ok: true });
    }

    const m = path.match(/^\/admin\/(announcements|posts)(?:\/([\w-]+))?$/);
    if (m) {
      const key = m[1];
      if (method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const title = clip(b.title, 100), body = clip(b.body, 5000);
        if (!title || !body) return J({ error: '제목과 내용을 입력하세요.' }, 400);
        const item = { id: crypto.randomUUID(), title, body, date: today() };
        if (key === 'posts') item.author = clip(b.author, 40) || '채리온 운영진';
        d[key].unshift(item);
        await save(env, d); return J({ ok: true, item });
      }
      if (method === 'DELETE' && m[2]) {
        d[key] = d[key].filter(x => x.id !== m[2]);
        await save(env, d); return J({ ok: true });
      }
    }
  }
  return J({ error: 'Not found' }, 404);
}

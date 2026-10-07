/**
 * checkin-worker — API-only port of checkin-panel to Cloudflare Workers.
 *
 * What this is: the HTTP check-in engine (probe / password & token & session
 * auth / endpoint & login_bonus check-in / JWT refresh), an account CRUD API,
 * and a cron sweep. D1 persists accounts with secrets encrypted at rest.
 *
 * What this is NOT: browser login, IdP session injection, Turnstile minting,
 * `visit`-mechanism check-ins, promo cards, the Windows desktop app.
 */

import { Hono } from 'hono';
import {
  bootstrapPassword,
  credentialsFromPaste,
  outcomeJson,
  probe,
  siteMechanismOf,
} from './newapi';
import { runCheckin, sweep, verifyCredential } from './scheduler';
import {
  accountPublic,
  createAccount,
  deleteAccount,
  getAccount,
  getCachedSite,
  listAccounts,
  setCachedSite,
  updateAccount,
  LOGIN_METHODS,
  type AccountInput,
  type Env,
} from './store';

const app = new Hono<{ Bindings: Env }>();

// ---------------------------------------------------------------------------
// Auth: the original panel had NO login (ADR-0003) and bound 127.0.0.1.
// On Workers everything is public, so a bearer token is required when
// ADMIN_TOKEN is set. Prefer Cloudflare Access in front for real deployments.
// ---------------------------------------------------------------------------
app.use('/api/*', async (c, next) => {
  const required = c.env.ADMIN_TOKEN;
  if (!required) return next(); // dev only — README says to set it
  const got = c.req.header('Authorization');
  if (got === `Bearer ${required}`) return next();
  return c.json({ detail: 'unauthorized' }, 401);
});

// ---------------------------------------------------------------------------
// Validation (mirrors panel/app.py::_check, narrowed to API-only methods)
// ---------------------------------------------------------------------------
const WINDOW = /^([01]?\d|2[0-3]):[0-5]\d$/;
const AVATAR_SLUG = /^[a-z]{2,16}$/;

function checkInput(input: Record<string, unknown>): Record<string, unknown> {
  const url = input['base_url'];
  if (url !== undefined && url !== null && !String(url).startsWith('http://') && !String(url).startsWith('https://')) {
    throw httpErr(422, 'base_url 必须以 http:// 或 https:// 开头');
  }
  const method = input['login_method'];
  if (method !== undefined && method !== null) {
    if (method === 'linuxdo' || method === 'github') {
      throw httpErr(422, `login_method '${method}' 需要浏览器登录，Worker 版不支持；请改用 password / access_token / session`);
    }
    if (!(LOGIN_METHODS as readonly string[]).includes(String(method))) {
      throw httpErr(422, `login_method 必须是 ${LOGIN_METHODS.join(' / ')} 之一`);
    }
  }
  const mechanism = input['mechanism'];
  if (mechanism !== undefined && mechanism !== null && mechanism !== 'auto') {
    throw httpErr(422, 'Worker 版只支持 auto 签到方式（visit 需要浏览器加载页面，不支持）');
  }
  const window = input['checkin_after'];
  if (window && !WINDOW.test(String(window))) {
    throw httpErr(422, '每日开放时间要写成 HH:MM，例如 08:30');
  }
  for (const [key, label] of [['avatar_color', '头像颜色'], ['avatar_shape', '头像样式']] as const) {
    const v = input[key];
    if (v !== undefined && v !== null && v !== '' && !AVATAR_SLUG.test(String(v))) {
      throw httpErr(422, `${label}要写成 2-16 位小写英文，例如 blue`);
    }
  }
  return input;
}

function httpErr(status: number, detail: string): Error {
  return Object.assign(new Error(detail), { status });
}

function toInput(body: Record<string, unknown>): AccountInput {
  const flat: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) {
    flat[k.replace(/([A-Z])/g, (m) => `_${m.toLowerCase()}`)] = v;
  }
  const input: AccountInput = {
    name: String(flat['name'] ?? ''),
    baseUrl: String(flat['base_url'] ?? ''),
  };
  if (flat['login_method'] !== undefined)
    input.loginMethod = flat['login_method'] as 'password' | 'access_token' | 'session';
  if (flat['username'] !== undefined) input.username = (flat['username'] as string) ?? null;
  if (flat['password'] !== undefined) input.password = (flat['password'] as string) ?? null;
  if (flat['access_token'] !== undefined) input.accessToken = (flat['access_token'] as string) ?? null;
  if (flat['session'] !== undefined) input.session = (flat['session'] as string) ?? null;
  if (flat['api_user'] !== undefined) input.apiUser = (flat['api_user'] as string) ?? null;
  if (flat['checkin_after'] !== undefined) input.checkinAfter = (flat['checkin_after'] as string) ?? null;
  if (flat['avatar_color'] !== undefined) input.avatarColor = (flat['avatar_color'] as string) ?? null;
  if (flat['avatar_shape'] !== undefined) input.avatarShape = (flat['avatar_shape'] as string) ?? null;
  if (flat['enabled'] !== undefined) input.enabled = Boolean(flat['enabled']);
  return input;
}

/**
 * Normalize a pasted `session` the way the original did: whatever shape it
 * arrived in, the column stores the credential itself.
 */
function normalizePaste(input: AccountInput): void {
  if (!input.session) return;
  try {
    const candidates = credentialsFromPaste(input.session);
    input.session = candidates[0]!.value;
  } catch (e) {
    throw httpErr(422, (e as Error).message);
  }
}

async function withCredentialCheck(
  env: Env,
  accountId: number,
  credentialChanged: boolean,
): Promise<{ account: Record<string, unknown>; credential: { ok: boolean; warning: string | null } | null }> {
  const account = await getAccount(env, accountId);
  if (!account) throw httpErr(404, 'Account not found');
  if (!credentialChanged) {
    return { account: accountPublic(account), credential: null };
  }
  let check: { ok: boolean; reason: string | null };
  try {
    check = await verifyCredential(env, account);
  } catch (e) {
    check = { ok: false, reason: `凭据没能验证：${e instanceof Error ? e.message : String(e)}` };
  }
  return {
    account: accountPublic(await getAccount(env, accountId) as NonNullable<Awaited<ReturnType<typeof getAccount>>>),
    credential: { ok: check.ok, warning: check.ok ? null : check.reason },
  };
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.get('/api/health', (c) => c.json({ ok: true, mode: 'api-only' }));

app.get('/api/accounts', async (c) => {
  const accounts = await listAccounts(c.env);
  return c.json(accounts.map(accountPublic));
});

app.post('/api/accounts', async (c) => {
  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || !body['name'] || !body['base_url']) throw httpErr(422, 'name 和 base_url 必填');
  checkInput(body);
  const input = toInput(body);
  normalizePaste(input);
  const created = await createAccount(c.env, input);
  const credentialChanged = Boolean(input.session || input.accessToken || input.password);
  return c.json(await withCredentialCheck(c.env, created.id, credentialChanged), 201);
});

app.get('/api/accounts/:id', async (c) => {
  const account = await getAccount(c.env, Number(c.req.param('id')));
  if (!account) throw httpErr(404, 'Account not found');
  return c.json(accountPublic(account));
});

app.put('/api/accounts/:id', async (c) => {
  const id = Number(c.req.param('id'));
  const before = await getAccount(c.env, id);
  if (!before) throw httpErr(404, 'Account not found');
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  checkInput(body);
  const input = toInput(body);
  normalizePaste(input);
  // Only a credential that actually changed is worth verifying: on a JWT fork
  // the check *spends* the refresh cookie and rotates it.
  const sessionChanged = input.session !== undefined && input.session !== before.session;
  const tokenChanged = input.accessToken !== undefined && input.accessToken !== before.accessToken;
  const passwordChanged = Boolean(input.password);
  const updated = await updateAccount(c.env, id, input);
  if (!updated) throw httpErr(404, 'Account not found');
  return c.json(await withCredentialCheck(c.env, id, sessionChanged || tokenChanged || passwordChanged));
});

app.delete('/api/accounts/:id', async (c) => {
  const ok = await deleteAccount(c.env, Number(c.req.param('id')));
  if (!ok) throw httpErr(404, 'Account not found');
  return c.json({ deleted: true });
});

app.post('/api/accounts/:id/check-in', async (c) => {
  const account = await getAccount(c.env, Number(c.req.param('id')));
  if (!account) throw httpErr(404, 'Account not found');
  try {
    const outcome = await runCheckin(c.env, account);
    return c.json(outcomeJson(outcome));
  } catch (e) {
    throw httpErr(502, e instanceof Error ? e.message : String(e));
  }
});

app.post('/api/check-in', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { account_ids?: number[] };
  const results: Record<string, unknown> = {};
  for (const id of body.account_ids ?? []) {
    const account = await getAccount(c.env, Number(id));
    if (!account) {
      results[String(id)] = { success: false, error: 'Account not found' };
      continue;
    }
    try {
      results[String(id)] = outcomeJson(await runCheckin(c.env, account));
    } catch (e) {
      results[String(id)] = { success: false, error: e instanceof Error ? e.message : String(e) };
    }
  }
  return c.json(results);
});

app.post('/api/probe', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { base_url?: string };
  checkInput({ base_url: body.base_url });
  try {
    const cached = await getCachedSite(c.env, String(body.base_url).replace(/\/+$/, ''));
    const info = cached ?? (await probe(String(body.base_url)));
    if (!cached) await setCachedSite(c.env, info);
    return c.json({ ...info, mechanism: siteMechanismOf(info) });
  } catch (e) {
    throw httpErr(502, e instanceof Error ? e.message : String(e));
  }
});

/**
 * Turn a session into a permanent username+password (PUT /api/user/self),
 * so every later check-in is pure HTTP. HTTP-only — kept.
 */
app.post('/api/accounts/:id/bootstrap', async (c) => {
  const account = await getAccount(c.env, Number(c.req.param('id')));
  if (!account) throw httpErr(404, 'Account not found');
  if (!account.session) throw httpErr(400, '该账号没有可用的 session 凭据');
  try {
    const { username, password } = await bootstrapPassword(account.baseUrl, account.session, {
      apiUser: account.apiUser,
    });
    await updateAccount(c.env, account.id, { username, password, loginMethod: 'password' });
    return c.json({ username });
  } catch (e) {
    throw httpErr(400, e instanceof Error ? e.message : String(e));
  }
});

// ---------------------------------------------------------------------------
// Errors & cron
// ---------------------------------------------------------------------------
app.onError((err, c) => {
  const status = (err as { status?: number }).status ?? 500;
  return c.json({ detail: err.message || 'internal error' }, status as 500);
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    await sweep(env);
  },
};

/**
 * D1-backed account store. Mirrors panel/store.py's accounts table, minus
 * promo_state (desktop UI concern) and plus encrypted secret columns.
 *
 * Plaintext never touches D1 for: password, access_token, session.
 * api_user is not a secret (it is the account's own id on the site).
 */

import { maybeDecrypt, maybeEncrypt } from './crypto';
import type { SiteInfo } from './newapi';

export const LOGIN_METHODS = ['password', 'access_token', 'session'] as const;
export type LoginMethod = (typeof LOGIN_METHODS)[number];

export interface Account {
  id: number;
  name: string;
  baseUrl: string;
  loginMethod: LoginMethod;
  username: string | null;
  password: string | null; // decrypted
  accessToken: string | null; // decrypted
  session: string | null; // decrypted
  apiUser: string | null;
  checkinAfter: string | null; // 'HH:MM'
  avatarColor: string | null;
  avatarShape: string | null;
  enabled: boolean;
  lastRunAt: string | null;
  lastSuccess: boolean | null;
  lastCheckedIn: boolean | null;
  lastQuota: number | null;
  lastError: string | null;
  failures: number;
  createdAt: string;
  updatedAt: string;
}

/** Public view: secrets replaced by presence flags. Never send secrets to a client. */
export function accountPublic(a: Account): Record<string, unknown> {
  const { password: _p, accessToken: _t, session: _s, ...rest } = a;
  void _p;
  void _t;
  void _s;
  return {
    ...rest,
    has_password: Boolean(a.password),
    has_access_token: Boolean(a.accessToken),
    has_session: Boolean(a.session),
  };
}

export interface Env {
  DB: D1Database;
  ADMIN_TOKEN?: string;
  ENCRYPTION_KEY: string;
  CHECKIN_TZ?: string;
}

const now = (): string => new Date().toISOString();

interface AccountRow {
  id: number;
  name: string;
  base_url: string;
  login_method: string;
  username: string | null;
  password: string | null;
  access_token: string | null;
  session: string | null;
  api_user: string | null;
  checkin_after: string | null;
  avatar_color: string | null;
  avatar_shape: string | null;
  enabled: number;
  last_run_at: string | null;
  last_success: number | null;
  last_checked_in: number | null;
  last_quota: number | null;
  last_error: string | null;
  failures: number;
  created_at: string;
  updated_at: string;
}

async function rowToAccount(env: Env, row: AccountRow): Promise<Account> {
  const flag = (v: number | null): boolean | null => (v === null ? null : Boolean(v));
  return {
    id: row.id,
    name: row.name,
    baseUrl: row.base_url,
    loginMethod: row.login_method as LoginMethod,
    username: row.username,
    password: await maybeDecrypt(env.ENCRYPTION_KEY, row.password),
    accessToken: await maybeDecrypt(env.ENCRYPTION_KEY, row.access_token),
    session: await maybeDecrypt(env.ENCRYPTION_KEY, row.session),
    apiUser: row.api_user,
    checkinAfter: row.checkin_after,
    avatarColor: row.avatar_color,
    avatarShape: row.avatar_shape,
    enabled: Boolean(row.enabled),
    lastRunAt: row.last_run_at,
    lastSuccess: flag(row.last_success),
    lastCheckedIn: flag(row.last_checked_in),
    lastQuota: row.last_quota,
    lastError: row.last_error,
    failures: row.failures ?? 0,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export interface AccountInput {
  name: string;
  baseUrl: string;
  loginMethod?: LoginMethod;
  username?: string | null;
  password?: string | null;
  accessToken?: string | null;
  session?: string | null;
  apiUser?: string | null;
  checkinAfter?: string | null;
  avatarColor?: string | null;
  avatarShape?: string | null;
  enabled?: boolean;
}

export async function listAccounts(env: Env): Promise<Account[]> {
  const { results } = await env.DB.prepare('SELECT * FROM accounts ORDER BY id').all<AccountRow>();
  return Promise.all((results ?? []).map((r) => rowToAccount(env, r)));
}

export async function listEnabled(env: Env): Promise<Account[]> {
  const { results } = await env.DB.prepare(
    "SELECT * FROM accounts WHERE enabled = 1 AND base_url != '' ORDER BY id",
  ).all<AccountRow>();
  return Promise.all((results ?? []).map((r) => rowToAccount(env, r)));
}

export async function getAccount(env: Env, id: number): Promise<Account | null> {
  const row = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(id).first<AccountRow>();
  return row ? rowToAccount(env, row) : null;
}

export async function createAccount(env: Env, input: AccountInput): Promise<Account> {
  const ts = now();
  try {
    const res = await env.DB.prepare(
      `INSERT INTO accounts
        (name, base_url, login_method, username, password, access_token, session,
         api_user, checkin_after, avatar_color, avatar_shape, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        input.name,
        input.baseUrl.replace(/\/+$/, ''),
        input.loginMethod ?? 'password',
        input.username ?? null,
        await maybeEncrypt(env.ENCRYPTION_KEY, input.password),
        await maybeEncrypt(env.ENCRYPTION_KEY, input.accessToken),
        await maybeEncrypt(env.ENCRYPTION_KEY, input.session),
        input.apiUser ?? null,
        input.checkinAfter ?? null,
        input.avatarColor ?? null,
        input.avatarShape ?? null,
        input.enabled === false ? 0 : 1,
        ts,
        ts,
      )
      .run();
    const created = await getAccount(env, Number(res.meta.last_row_id));
    if (!created) throw new Error('account created but could not be read back');
    return created;
  } catch (e) {
    if (String((e as Error).message).includes('UNIQUE')) {
      throw Object.assign(new Error('这个网站下已经有同名账号了，换个名称'), { status: 409 });
    }
    throw e;
  }
}

export async function updateAccount(
  env: Env,
  id: number,
  fields: Partial<Omit<AccountInput, 'name' | 'baseUrl'>> & { name?: string; baseUrl?: string },
): Promise<Account | null> {
  const sets: string[] = [];
  const values: unknown[] = [];
  const map: Record<string, string> = {
    name: 'name',
    baseUrl: 'base_url',
    loginMethod: 'login_method',
    username: 'username',
    apiUser: 'api_user',
    checkinAfter: 'checkin_after',
    avatarColor: 'avatar_color',
    avatarShape: 'avatar_shape',
  };
  for (const [k, col] of Object.entries(map)) {
    const v = (fields as Record<string, unknown>)[k];
    if (v !== undefined) {
      sets.push(`${col} = ?`);
      values.push(k === 'baseUrl' ? String(v).replace(/\/+$/, '') : (v as string | null));
    }
  }
  if (fields.password !== undefined) {
    sets.push('password = ?');
    values.push(await maybeEncrypt(env.ENCRYPTION_KEY, fields.password || null));
  }
  if (fields.accessToken !== undefined) {
    sets.push('access_token = ?');
    values.push(await maybeEncrypt(env.ENCRYPTION_KEY, fields.accessToken || null));
  }
  if (fields.session !== undefined) {
    sets.push('session = ?');
    values.push(await maybeEncrypt(env.ENCRYPTION_KEY, fields.session || null));
  }
  if (fields.enabled !== undefined) {
    sets.push('enabled = ?');
    values.push(fields.enabled ? 1 : 0);
  }
  if (!sets.length) return getAccount(env, id);
  sets.push('updated_at = ?');
  values.push(now(), id);
  try {
    await env.DB.prepare(`UPDATE accounts SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
  } catch (e) {
    if (String((e as Error).message).includes('UNIQUE')) {
      throw Object.assign(new Error('这个网站下已经有同名账号了，换个名称'), { status: 409 });
    }
    throw e;
  }
  return getAccount(env, id);
}

export async function deleteAccount(env: Env, id: number): Promise<boolean> {
  const res = await env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(id).run();
  return (res.meta.changes ?? 0) > 0;
}

export interface RunResult {
  success: boolean;
  checkedIn: boolean | null;
  quota: number | null; // after_quota preferred, falls back to before
  error: string | null;
}

/**
 * Store one run's result. An unknown quota keeps the last known one —
 * blanking the balance because one reading failed is worse than a stale number.
 */
export async function recordResult(env: Env, id: number, r: RunResult): Promise<void> {
  await env.DB.prepare(
    `UPDATE accounts SET
       last_success = ?,
       last_checked_in = ?,
       last_quota = COALESCE(?, last_quota),
       last_error = ?,
       last_run_at = ?,
       updated_at = ?,
       failures = CASE WHEN ? THEN 0 ELSE failures + 1 END
     WHERE id = ?`,
  )
    .bind(
      r.success ? 1 : 0,
      r.checkedIn === null ? null : r.checkedIn ? 1 : 0,
      r.quota,
      r.error,
      now(),
      now(),
      r.success ? 1 : 0,
      id,
    )
    .run();
}

/** Persist rotated credentials an Outcome carries back (session / access_token / api_user / username). */
export async function persistRotated(
  env: Env,
  id: number,
  o: { session?: string | null; accessToken?: string | null; apiUser?: string | null; username?: string | null },
): Promise<void> {
  const sets: string[] = [];
  const values: unknown[] = [];
  if (o.session !== undefined && o.session !== null) {
    sets.push('session = ?');
    values.push(await maybeEncrypt(env.ENCRYPTION_KEY, o.session));
  }
  if (o.accessToken !== undefined && o.accessToken !== null) {
    sets.push('access_token = ?');
    values.push(await maybeEncrypt(env.ENCRYPTION_KEY, o.accessToken));
  }
  if (o.apiUser !== undefined && o.apiUser !== null) {
    sets.push('api_user = ?');
    values.push(o.apiUser);
  }
  if (o.username !== undefined && o.username !== null) {
    sets.push('username = ?');
    values.push(o.username);
  }
  if (!sets.length) return;
  sets.push('updated_at = ?');
  values.push(now(), id);
  await env.DB.prepare(`UPDATE accounts SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
}

// ---------------------------------------------------------------------------
// Site-info probe cache (24h TTL)
// ---------------------------------------------------------------------------

const SITE_TTL_MS = 24 * 3600 * 1000;

export async function getCachedSite(env: Env, baseUrl: string): Promise<SiteInfo | null> {
  const row = await env.DB.prepare('SELECT info_json, probed_at FROM site_info WHERE base_url = ?')
    .bind(baseUrl)
    .first<{ info_json: string; probed_at: string }>();
  if (!row) return null;
  if (Date.now() - new Date(row.probed_at).getTime() > SITE_TTL_MS) return null;
  try {
    return JSON.parse(row.info_json) as SiteInfo;
  } catch {
    return null;
  }
}

export async function setCachedSite(env: Env, site: SiteInfo): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO site_info (base_url, info_json, probed_at) VALUES (?, ?, ?)
     ON CONFLICT(base_url) DO UPDATE SET info_json = excluded.info_json, probed_at = excluded.probed_at`,
  )
    .bind(site.baseUrl, JSON.stringify(site), now())
    .run();
}

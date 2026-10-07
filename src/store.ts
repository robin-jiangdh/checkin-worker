/**
 * KV-backed account store. Mirrors panel/store.py's accounts table, minus
 * promo_state (desktop UI concern) and plus encrypted secret columns.
 *
 * NOTE: D1 was the original design, but Robin's stored Cloudflare API token
 * has no D1 scope (Workers + KV only), so storage is KV. If the token is ever
 * replaced with D1 scope, see migrations/0001_accounts.sql for the D1 schema.
 *
 * Layout:
 *   acct:{id}   -> account row JSON (snake_case, secrets AES-GCM encrypted)
 *   acct:index  -> number[] of account ids, insertion order
 *   acct:seq    -> next account id
 *   site:{b64}  -> cached SiteInfo JSON, expirationTtl 86400 (24h)
 *
 * Plaintext never touches KV for: password, access_token, session.
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
  KV: KVNamespace;
  ADMIN_TOKEN?: string;
  ENCRYPTION_KEY: string;
  CHECKIN_TZ?: string;
}

const now = (): string => new Date().toISOString();

/** Stored row: snake_case, secret columns hold AES-GCM ciphertext. */
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

const rowKey = (id: number): string => `acct:${id}`;
const INDEX_KEY = 'acct:index';
const SEQ_KEY = 'acct:seq';

async function readRow(env: Env, id: number): Promise<AccountRow | null> {
  const raw = await env.KV.get(rowKey(id));
  return raw ? (JSON.parse(raw) as AccountRow) : null;
}

async function writeRow(env: Env, row: AccountRow): Promise<void> {
  await env.KV.put(rowKey(row.id), JSON.stringify(row));
}

async function readIndex(env: Env): Promise<number[]> {
  const raw = await env.KV.get(INDEX_KEY);
  if (!raw) return [];
  try {
    const ids = JSON.parse(raw) as unknown;
    return Array.isArray(ids) ? (ids as number[]) : [];
  } catch {
    return [];
  }
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

function uniqueErr(): Error {
  return Object.assign(new Error('这个网站下已经有同名账号了，换个名称'), { status: 409 });
}

export async function listAccounts(env: Env): Promise<Account[]> {
  const ids = await readIndex(env);
  const out: Account[] = [];
  for (const id of ids) {
    const row = await readRow(env, id);
    if (row) out.push(await rowToAccount(env, row));
  }
  return out;
}

export async function listEnabled(env: Env): Promise<Account[]> {
  return (await listAccounts(env)).filter((a) => a.enabled && a.baseUrl);
}

export async function getAccount(env: Env, id: number): Promise<Account | null> {
  const row = await readRow(env, id);
  return row ? rowToAccount(env, row) : null;
}

export async function createAccount(env: Env, input: AccountInput): Promise<Account> {
  const baseUrl = input.baseUrl.replace(/\/+$/, '');
  const existing = await listAccounts(env);
  if (existing.some((a) => a.name === input.name && a.baseUrl === baseUrl)) throw uniqueErr();

  const seqRaw = await env.KV.get(SEQ_KEY);
  const id = (seqRaw ? parseInt(seqRaw, 10) : 0) + 1;
  const ts = now();
  const row: AccountRow = {
    id,
    name: input.name,
    base_url: baseUrl,
    login_method: input.loginMethod ?? 'password',
    username: input.username ?? null,
    password: await maybeEncrypt(env.ENCRYPTION_KEY, input.password),
    access_token: await maybeEncrypt(env.ENCRYPTION_KEY, input.accessToken),
    session: await maybeEncrypt(env.ENCRYPTION_KEY, input.session),
    api_user: input.apiUser ?? null,
    checkin_after: input.checkinAfter ?? null,
    avatar_color: input.avatarColor ?? null,
    avatar_shape: input.avatarShape ?? null,
    enabled: input.enabled === false ? 0 : 1,
    last_run_at: null,
    last_success: null,
    last_checked_in: null,
    last_quota: null,
    last_error: null,
    failures: 0,
    created_at: ts,
    updated_at: ts,
  };
  await writeRow(env, row);
  await env.KV.put(SEQ_KEY, String(id));
  await env.KV.put(INDEX_KEY, JSON.stringify([...(await readIndex(env)), id]));
  const created = await getAccount(env, id);
  if (!created) throw new Error('account created but could not be read back');
  return created;
}

export async function updateAccount(
  env: Env,
  id: number,
  fields: Partial<Omit<AccountInput, 'name' | 'baseUrl'>> & { name?: string; baseUrl?: string },
): Promise<Account | null> {
  const row = await readRow(env, id);
  if (!row) return null;

  const nextName = fields.name ?? row.name;
  const nextBase = (fields.baseUrl ?? row.base_url).replace(/\/+$/, '');
  const others = await listAccounts(env);
  if (others.some((a) => a.id !== id && a.name === nextName && a.baseUrl === nextBase)) throw uniqueErr();

  row.name = nextName;
  row.base_url = nextBase;
  if (fields.loginMethod !== undefined) row.login_method = fields.loginMethod;
  if (fields.username !== undefined) row.username = fields.username;
  if (fields.apiUser !== undefined) row.api_user = fields.apiUser;
  if (fields.checkinAfter !== undefined) row.checkin_after = fields.checkinAfter;
  if (fields.avatarColor !== undefined) row.avatar_color = fields.avatarColor;
  if (fields.avatarShape !== undefined) row.avatar_shape = fields.avatarShape;
  if (fields.password !== undefined) row.password = await maybeEncrypt(env.ENCRYPTION_KEY, fields.password || null);
  if (fields.accessToken !== undefined)
    row.access_token = await maybeEncrypt(env.ENCRYPTION_KEY, fields.accessToken || null);
  if (fields.session !== undefined) row.session = await maybeEncrypt(env.ENCRYPTION_KEY, fields.session || null);
  if (fields.enabled !== undefined) row.enabled = fields.enabled ? 1 : 0;
  row.updated_at = now();
  await writeRow(env, row);
  return getAccount(env, id);
}

export async function deleteAccount(env: Env, id: number): Promise<boolean> {
  const row = await readRow(env, id);
  if (!row) return false;
  await env.KV.delete(rowKey(id));
  await env.KV.put(INDEX_KEY, JSON.stringify((await readIndex(env)).filter((i) => i !== id)));
  return true;
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
  const row = await readRow(env, id);
  if (!row) return;
  const ts = now();
  row.last_success = r.success ? 1 : 0;
  row.last_checked_in = r.checkedIn === null ? null : r.checkedIn ? 1 : 0;
  if (r.quota !== null) row.last_quota = r.quota;
  row.last_error = r.error;
  row.last_run_at = ts;
  row.updated_at = ts;
  row.failures = r.success ? 0 : row.failures + 1;
  await writeRow(env, row);
}

/** Persist rotated credentials an Outcome carries back (session / access_token / api_user / username). */
export async function persistRotated(
  env: Env,
  id: number,
  o: { session?: string | null; accessToken?: string | null; apiUser?: string | null; username?: string | null },
): Promise<void> {
  const row = await readRow(env, id);
  if (!row) return;
  let touched = false;
  if (o.session !== undefined && o.session !== null) {
    row.session = await maybeEncrypt(env.ENCRYPTION_KEY, o.session);
    touched = true;
  }
  if (o.accessToken !== undefined && o.accessToken !== null) {
    row.access_token = await maybeEncrypt(env.ENCRYPTION_KEY, o.accessToken);
    touched = true;
  }
  if (o.apiUser !== undefined && o.apiUser !== null) {
    row.api_user = o.apiUser;
    touched = true;
  }
  if (o.username !== undefined && o.username !== null) {
    row.username = o.username;
    touched = true;
  }
  if (!touched) return;
  row.updated_at = now();
  await writeRow(env, row);
}

// ---------------------------------------------------------------------------
// Site-info probe cache (24h TTL via KV expiration)
// ---------------------------------------------------------------------------

const SITE_TTL_S = 24 * 3600;

function siteKey(baseUrl: string): string {
  const b64 = btoa(baseUrl).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `site:${b64}`;
}

export async function getCachedSite(env: Env, baseUrl: string): Promise<SiteInfo | null> {
  const raw = await env.KV.get(siteKey(baseUrl));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SiteInfo;
  } catch {
    return null;
  }
}

export async function setCachedSite(env: Env, site: SiteInfo): Promise<void> {
  await env.KV.put(siteKey(site.baseUrl), JSON.stringify(site), { expirationTtl: SITE_TTL_S });
}

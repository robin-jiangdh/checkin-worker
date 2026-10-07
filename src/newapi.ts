/**
 * Protocol-level New API client for Cloudflare Workers — no browser, no UI automation.
 *
 * TypeScript port of panel/newapi.py (BingLi37/checkin-panel), API-only subset:
 * probe / password login / access-token & session auth / JWT refresh /
 * endpoint check-in / login_bonus check-in / bootstrap password.
 *
 * Deliberately NOT ported: browser login, IdP session injection, Turnstile
 * minting, `visit`-mechanism check-ins, promo cards.
 */

export const DEFAULT_QUOTA_PER_UNIT = 500_000.0;
const TIMEOUT_MS = 25_000;

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// Most specific first: a fork that adds its own check-in usually leaves the
// generic route registered as well — and the generic one may be the disabled
// one (sotamodel.net), so first-match order picks the working route.
const CHECKIN_CANDIDATES = [
  '/api/user/sota-agent-checkin',
  '/api/user/checkin',
  '/api/user/check_in',
  '/api/user/sign_in',
  '/api/user/clock_in',
];

const REFRESH_PATH = '/api/user/auth/refresh'; // JWT forks: trade the refresh cookie for a Bearer <redacted>
const REFRESH_COOKIE = 'new_api_refresh';

// The only two cookies that authenticate anything, most common first.
const CREDENTIAL_COOKIES = ['session', REFRESH_COOKIE] as const;

const OAUTH_FLAGS = ['linuxdo', 'github', 'oidc', 'telegram', 'wechat'] as const;

const ALREADY_DONE = /已签到|已经签到|重复签到|already/i;
const CHECKIN_LOG = /签到|check.?in/i;
const NEEDS_API_USER = /new[-_ ]?api[-_ ]?user/i;

const SYSTEM_LOG_TYPE = 4; // New API: 1 topup, 2 consume, 3 manage, 4 system, 5 error

// ---------------------------------------------------------------------------
// Credential parsing (paste shapes)
// ---------------------------------------------------------------------------

export interface PastedCredential {
  value: string;
  cookieName: string;
}

function cookieDicts(parsed: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(parsed)) return parsed.filter((c): c is Record<string, unknown> => typeof c === 'object' && c !== null);
  if (typeof parsed !== 'object' || parsed === null) return [];
  const d = parsed as Record<string, unknown>;
  if (typeof d['name'] === 'string' && 'value' in d) return [d]; // one exported cookie
  // Bare mapping. Only string values can be a credential.
  return Object.entries(d)
    .filter(([, v]) => typeof v === 'string')
    .map(([k, v]) => ({ name: k, value: v as string }));
}

function credentialsIn(cookies: Array<Record<string, unknown>>): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  for (const name of CREDENTIAL_COOKIES) {
    for (const cookie of cookies) {
      if (cookie['name'] === name && typeof cookie['value'] === 'string' && cookie['value']) {
        found.push([name, cookie['value'] as string]);
      }
    }
  }
  return found;
}

/** Lenient: accept a bare value, `session=v; …`, a JSON dict, or an exported cookie list. */
export function parseSession(raw: string | null | undefined): string | null {
  const text = (raw ?? '').trim();
  if (!text) return null;
  if (text[0] === '{' || text[0] === '[') {
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    if (parsed !== null) {
      const found = credentialsIn(cookieDicts(parsed));
      if (found.length) return found[0]![1];
      // Understood as JSON but nothing in it authenticates — fall through to
      // first string value rather than handing back a blob the site rejects.
      const dicts = cookieDicts(parsed);
      for (const c of dicts) {
        if (typeof c['value'] === 'string' && c['value']) return c['value'] as string;
      }
      return null;
    }
  }
  const m = /(?:^|;\s*)session=([^;]+)/.exec(text);
  if (m) return m[1]!.trim();
  return text;
}

/** Strict: what a human just pasted. Raises if there is no credential in it. */
export function credentialsFromPaste(raw: string | null | undefined): PastedCredential[] {
  const text = (raw ?? '').trim();
  if (!text) throw new Error('没有粘贴任何内容');
  if (text[0] === '{' || text[0] === '[') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error(`这段内容看起来是 JSON，但解析失败：${(e as Error).message}`);
    }
    const cookies = cookieDicts(parsed);
    const found = credentialsIn(cookies);
    if (found.length) return found.map(([name, value]) => ({ value, cookieName: name }));
    const names = cookies.map((c) => String(c['name'] ?? '')).filter(Boolean);
    const listed = names.length ? names.slice(0, 8).join('、') + (names.length > 8 ? '…' : '') : '没有任何 cookie';
    throw new Error(
      `这段 JSON 里没有 ${CREDENTIAL_COOKIES.join(' 也没有 ')}，只找到：${listed}。请在站点的已登录页面导出 cookie，再整段粘进来`,
    );
  }
  const value = parseSession(text);
  if (!value) throw new Error('这段内容里找不到可用的凭据');
  return [{ value, cookieName: 'session' }];
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SiteInfo {
  baseUrl: string;
  /** Empty = the site did not say (e.g. WAF answered), NOT "password only". */
  loginMethods: string[];
  quotaPerUnit: number;
  turnstile: boolean;
  turnstileKey: string | null;
  checkinPath: string | null;
  refreshPath: string | null;
  statusPath: string | null;
  checkinEnabled: boolean | null;
}

export type LoginMethod = 'password' | 'access_token' | 'session';

export interface Login {
  baseUrl: string;
  loginMethod?: LoginMethod;
  username?: string | null;
  password?: string | null;
  accessToken?: string | null;
  session?: string | null;
  apiUser?: string | null;
}

export interface Outcome {
  success: boolean;
  checkedIn: boolean | null;
  beforeQuota: number | null;
  afterQuota: number | null;
  error: string | null;
  session: string | null; // fresh session worth persisting
  accessToken: string | null;
  apiUser: string | null;
  username: string | null;
  awarded: number | null; // USD the site itself said it just granted
}

export interface CheckinStatus {
  today: boolean | null;
  awardedToday: number | null;
  reward: number | null;
  total: number | null;
}

export function outcomeDelta(o: Outcome): number | null {
  if (o.beforeQuota === null || o.afterQuota === null) return null;
  return Math.round((o.afterQuota - o.beforeQuota) * 100) / 100;
}

export function outcomeGain(o: Outcome): number | null {
  return o.awarded !== null ? o.awarded : outcomeDelta(o);
}

function siteMechanism(site: SiteInfo): 'endpoint' | 'login_bonus' {
  return site.checkinPath ? 'endpoint' : 'login_bonus';
}

// ---------------------------------------------------------------------------
// Minimal cookie jar (Workers fetch has no jar)
// ---------------------------------------------------------------------------

class CookieJar {
  private store = new Map<string, string>();

  set(name: string, value: string): void {
    this.store.set(name, value);
  }

  clear(): void {
    this.store.clear();
  }

  header(): string | null {
    if (!this.store.size) return null;
    return [...this.store.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  /** Absorb Set-Cookie headers; returns the value set for `name`, if any. */
  absorb(headers: Headers, name: string): string | null {
    const raw: string[] =
      typeof (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === 'function'
        ? (headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
        : (() => {
            const h = headers.get('set-cookie');
            return h ? [h] : [];
          })();
    let found: string | null = null;
    for (const line of raw) {
      const m = /^([^=;]+)=([^;]*)/.exec(line.trim());
      if (m && m[1]!.trim().toLowerCase() === name.toLowerCase()) {
        const v = m[2]!.trim();
        this.store.set(name, v);
        found = v;
      }
    }
    return found;
  }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

export interface Creds {
  session?: string | null;
  accessToken?: string | null;
  apiUser?: string | null;
}

function buildHeaders(baseUrl: string, creds: Creds, jar: CookieJar | null): Headers {
  const headers = new Headers({
    Accept: 'application/json',
    'User-Agent': UA,
    // Some forks 403 `AUTH_ORIGIN_FORBIDDEN` without this; a browser sets it
    // on its own and fetch does not.
    Origin: baseUrl.replace(/\/+$/, ''),
  });
  if (creds.accessToken) headers.set('Authorization', creds.accessToken);
  if (creds.apiUser) headers.set('new-api-user', String(creds.apiUser));
  if (jar) {
    const cookie = jar.header();
    if (cookie) headers.set('Cookie', cookie);
  } else if (creds.session) {
    headers.set('Cookie', `session=${creds.session}`);
  }
  return headers;
}

async function req(
  baseUrl: string,
  path: string,
  init: RequestInit,
  creds: Creds,
  jar: CookieJar | null,
): Promise<Response> {
  const url = baseUrl.replace(/\/+$/, '') + path;
  const headers = buildHeaders(baseUrl, creds, jar);
  for (const [k, v] of new Headers(init.headers ?? {}).entries()) headers.set(k, v);
  const res = await fetch(url, {
    ...init,
    headers,
    redirect: 'follow',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (jar) {
    jar.absorb(res.headers, 'session');
    jar.absorb(res.headers, REFRESH_COOKIE);
  }
  return res;
}

export function why(e: unknown): string {
  const text = e instanceof Error ? e.message.trim() : String(e ?? '').trim();
  const kind = e instanceof Error ? e.name : 'Error';
  return text ? `${kind}: ${text}` : kind;
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  const ct = response.headers.get('content-type') ?? '';
  if (!ct.includes('json')) {
    return { success: false, message: `HTTP ${response.status} (非 JSON 响应)` };
  }
  try {
    const body: unknown = await response.json();
    if (body && typeof body === 'object' && !Array.isArray(body)) return body as Record<string, unknown>;
    return { success: false, message: String(body).slice(0, 200) };
  } catch {
    return { success: false, message: `HTTP ${response.status} (非 JSON 响应)` };
  }
}

function fail(body: Record<string, unknown>, response: Response): string {
  let message: unknown = body['message'] ?? body['error'] ?? `HTTP ${response.status}`;
  if (message && typeof message === 'object') {
    message = (message as Record<string, unknown>)['message'] ?? message;
  }
  return String(message);
}

function usdRaw(quota: unknown, perUnit: number): number | null {
  if (typeof quota !== 'number' || !Number.isFinite(quota)) return null;
  return Math.round((quota / (perUnit || DEFAULT_QUOTA_PER_UNIT)) * 100) / 100;
}

function usdOf(data: Record<string, unknown> | null, perUnit: number): number | null {
  return usdRaw(data?.['quota'], perUnit);
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async function selfGet(
  baseUrl: string,
  creds: Creds,
  jar: CookieJar | null,
): Promise<{ data: Record<string, unknown> | null; error: string | null }> {
  const response = await req(baseUrl, '/api/user/self', { method: 'GET' }, creds, jar);
  const body = await bodyOf(response);
  if (response.status === 200 && body['success']) {
    const data = body['data'];
    return { data: (data && typeof data === 'object' ? (data as Record<string, unknown>) : {}) ?? {}, error: null };
  }
  const message = fail(body, response);
  if (!creds.apiUser && NEEDS_API_USER.test(message)) {
    return { data: null, error: `${message}（凭据本身没问题，但这个站点还要账号的用户 id，请填 API User）` };
  }
  return { data: null, error: message };
}

/** (the user behind a credential, why it failed) */
export async function authenticate(
  baseUrl: string,
  creds: Creds,
): Promise<{ data: Record<string, unknown> | null; error: string | null }> {
  return selfGet(baseUrl, creds, null);
}

export async function whoami(baseUrl: string, creds: Creds): Promise<Record<string, unknown> | null> {
  const { data } = await authenticate(baseUrl, creds);
  return data;
}

export async function balance(baseUrl: string, quotaPerUnit: number, creds: Creds): Promise<number | null> {
  return usdOf(await whoami(baseUrl, creds), quotaPerUnit);
}

/**
 * Trade a `new_api_refresh` cookie for a Bearer <redacted> Returns
 * (access token, rotated refresh cookie or null, user).
 */
export async function refreshAccess(
  baseUrl: string,
  refresh: string,
): Promise<{ token: string | null; rotated: string | null; user: Record<string, unknown> }> {
  const jar = new CookieJar();
  jar.set(REFRESH_COOKIE, refresh);
  const response = await req(baseUrl, REFRESH_PATH, { method: 'POST' }, {}, jar);
  const body = await bodyOf(response);
  if (!body['success']) return { token: null, rotated: null, user: {} };
  const data = (body['data'] && typeof body['data'] === 'object' ? body['data'] : {}) as Record<string, unknown>;
  const rotated = jar.absorb(response.headers, REFRESH_COOKIE);
  return {
    token: typeof data['access_token'] === 'string' ? (data['access_token'] as string) : null,
    // Never return the spent value as "rotated": returning it would kill the
    // account on the next run. Null = the one we have is still live.
    rotated: rotated && rotated !== refresh ? rotated : null,
    user: (data['user'] && typeof data['user'] === 'object' ? data['user'] : {}) as Record<string, unknown>,
  };
}

// ---------------------------------------------------------------------------
// probe — what a site supports (all unauthenticated on purpose)
// ---------------------------------------------------------------------------

export async function probe(baseUrl: string): Promise<SiteInfo> {
  const base = baseUrl.replace(/\/+$/, '');
  const info: SiteInfo = {
    baseUrl: base,
    loginMethods: [],
    quotaPerUnit: DEFAULT_QUOTA_PER_UNIT,
    turnstile: false,
    turnstileKey: null,
    checkinPath: null,
    refreshPath: null,
    statusPath: null,
    checkinEnabled: null,
  };

  let statusData: Record<string, unknown> | null = null;
  try {
    const response = await req(base, '/api/status', { method: 'GET' }, {}, null);
    const body = await bodyOf(response);
    const data = body['data'];
    if (data && typeof data === 'object') statusData = data as Record<string, unknown>;
  } catch (e) {
    throw new Error(`无法访问 ${base}: ${why(e)}`);
  }

  // Read flags only if the site actually answered with its status. A WAF
  // answers 200 HTML to every path, which bodyOf turns into a failure dict —
  // indistinguishable from "no OAuth", so an unreadable status leaves the
  // tuple empty (absent, not false).
  if (statusData && Object.keys(statusData).length > 0) {
    info.loginMethods = [
      'password',
      ...OAUTH_FLAGS.filter((k) => statusData![`${k}_oauth`]),
    ];
    const qpu = statusData['quota_per_unit'];
    info.quotaPerUnit = typeof qpu === 'number' && qpu > 0 ? qpu : DEFAULT_QUOTA_PER_UNIT;
    info.turnstile = Boolean(statusData['turnstile_check']);
    info.turnstileKey =
      typeof statusData['turnstile_site_key'] === 'string' ? (statusData['turnstile_site_key'] as string) : null;
    const enabled = statusData['checkin_enabled'];
    info.checkinEnabled = typeof enabled === 'boolean' ? enabled : null;
  }

  // POST-only detection. A GET probe is worthless: GET /api/user/checkin
  // matches the admin route /api/user/:id and answers 200.
  for (const path of CHECKIN_CANDIDATES) {
    try {
      const response = await req(
        base,
        path,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        {},
        null,
      );
      // JSON or it did not happen: a WAF challenge answers 200 HTML to every
      // path, which would make every site look like an endpoint one.
      const ct = response.headers.get('content-type') ?? '';
      if (response.status !== 404 && ct.includes('json')) {
        info.checkinPath = path;
        break;
      }
    } catch {
      continue;
    }
  }

  if (info.checkinPath) {
    // Does the same path answer GET with a status read? 401 is the proof the
    // route exists and wants a credential; 200 would be the admin route
    // eating the segment.
    try {
      const response = await req(base, info.checkinPath, { method: 'GET' }, {}, null);
      const ct = response.headers.get('content-type') ?? '';
      if (response.status === 401 && ct.includes('json')) info.statusPath = info.checkinPath;
    } catch {
      /* cannot say */
    }
  }

  try {
    // 401 here means the fork authenticates with JWTs, not session cookies.
    const response = await req(base, REFRESH_PATH, { method: 'POST' }, {}, null);
    const ct = response.headers.get('content-type') ?? '';
    if (response.status !== 404 && ct.includes('json')) info.refreshPath = REFRESH_PATH;
  } catch {
    /* cannot say */
  }

  return info;
}

// ---------------------------------------------------------------------------
// check-in
// ---------------------------------------------------------------------------

async function passwordLogin(
  baseUrl: string,
  jar: CookieJar,
  login: Login,
): Promise<{ data: Record<string, unknown> | null; error: string | null; apiUser: string | null }> {
  if (!login.username || !login.password) return { data: null, error: '缺少用户名/密码', apiUser: null };
  const response = await req(
    baseUrl,
    '/api/user/login',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: login.username, password: login.password }),
    },
    { apiUser: login.apiUser ?? null },
    jar,
  );
  const body = await bodyOf(response);
  if (!body['success']) return { data: null, error: fail(body, response), apiUser: null };
  const data = (body['data'] && typeof body['data'] === 'object' ? body['data'] : {}) as Record<string, unknown>;
  // Some forks validate `new-api-user` against the session and 401 every
  // authenticated route without it — the SPA sends it, so we remember it.
  const apiUser = data['id'] !== undefined && data['id'] !== null ? String(data['id']) : null;
  return { data, error: null, apiUser };
}

function failOutcome(error: string, partial?: Partial<Outcome>): Outcome {
  return {
    success: false,
    checkedIn: null,
    beforeQuota: null,
    afterQuota: null,
    error,
    session: null,
    accessToken: null,
    apiUser: null,
    username: null,
    awarded: null,
    ...partial,
  };
}

async function checkInEndpoint(login: Login, site: SiteInfo): Promise<Outcome> {
  const jar = new CookieJar();
  const creds: Creds = {
    session: login.session ?? null,
    accessToken: login.accessToken ?? null,
    apiUser: login.apiUser ?? null,
  };
  // Seed the jar from a pasted session so the server-set cookie logic below
  // can tell "server rotated it" apart from "nothing came back".
  if (login.session && !login.accessToken) jar.set('session', login.session);

  let adopted = login.apiUser ?? null;

  if (!login.session && !login.accessToken) {
    const r = await passwordLogin(site.baseUrl, jar, login);
    if (r.error) return failOutcome(`登录失败: ${r.error}`);
    adopted = r.apiUser ?? adopted;
  }

  const headersFor = (): Creds => ({
    session: null,
    accessToken: creds.accessToken ?? null,
    apiUser: adopted,
  });

  // Authenticated reads go through the jar: the session cookie lives there so
  // a server-side rotation is picked up automatically.
  let before = await selfGet(site.baseUrl, headersFor(), jar);

  if (before.data === null && login.username && login.password) {
    // Dead session, or a fork demanding new-api-user we do not have yet.
    // A password login fixes both: it adopts the id from its response.
    jar.clear();
    const r = await passwordLogin(site.baseUrl, jar, login);
    if (r.error) return failOutcome(`登录失败: ${r.error}`, { session: login.session ?? null });
    adopted = r.apiUser ?? adopted;
    before = await selfGetViaJar(site.baseUrl, jar, creds.accessToken ?? null, adopted);
    if (before.data === null && !login.password) {
      // Carry the credential out even in failure: a JWT fork rotated its
      // refresh cookie a moment ago, and dropping it bricks the account.
      return failOutcome(`凭据无效: ${before.error}`, { session: login.session ?? null });
    }
  }

  const response = await req(
    site.baseUrl,
    site.checkinPath!,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
    { session: null, accessToken: creds.accessToken ?? null, apiUser: adopted },
    jar,
  );
  const body = await bodyOf(response);
  const granted = body['data'] && typeof body['data'] === 'object' ? (body['data'] as Record<string, unknown>) : {};
  const after = await selfGetViaJar(site.baseUrl, jar, creds.accessToken ?? null, adopted);

  // Some forks report the result: {quota_awarded, current_quota}. current_quota
  // is the balance *after* the grant, straight from the site — beats a second
  // read that could race with usage.
  const afterQuota =
    usdRaw(granted['current_quota'], site.quotaPerUnit) ?? usdOf(after.data, site.quotaPerUnit);

  const outcome: Outcome = {
    success: Boolean(body['success']),
    checkedIn: Boolean(body['success']),
    beforeQuota: usdOf(before.data, site.quotaPerUnit),
    afterQuota,
    error: null,
    session: jarValue(jar, 'session') ?? login.session ?? null,
    accessToken: login.accessToken ?? null,
    apiUser: adopted,
    username: null,
    awarded: usdRaw(granted['quota_awarded'], site.quotaPerUnit),
  };
  if (!outcome.success) {
    const message = fail(body, response);
    if (ALREADY_DONE.test(message)) {
      outcome.success = true;
      outcome.checkedIn = false;
      return outcome;
    }
    outcome.error = message;
  }
  return outcome;
}

async function selfGetViaJar(
  baseUrl: string,
  jar: CookieJar,
  accessToken: string | null,
  apiUser: string | null,
): Promise<{ data: Record<string, unknown> | null; error: string | null }> {
  return selfGet(baseUrl, { session: null, accessToken, apiUser }, jar);
}

function jarValue(jar: CookieJar, name: string): string | null {
  const header = jar.header();
  if (!header) return null;
  const m = new RegExp(`(?:^|;\\s*)${name}=([^;]+)`).exec(header);
  return m ? m[1]!.trim() : null;
}

async function checkInLoginBonus(login: Login, site: SiteInfo): Promise<Outcome> {
  // No check-in route: a fresh login IS the check-in.
  if (!login.username || !login.password) {
    return failOutcome(
      '该站点靠"重新登录"发放额度，而当前凭据无法重新登录。请填账号密码（Worker 版不支持浏览器登录）。',
    );
  }
  const jar = new CookieJar();
  if (login.session) jar.set('session', login.session);
  const before = await selfGetViaJar(site.baseUrl, jar, null, login.apiUser ?? null);
  jar.clear(); // a fresh login replaces the old session, it does not stack
  const r = await passwordLogin(site.baseUrl, jar, login);
  if (r.error) {
    return failOutcome(`登录失败: ${r.error}`, { beforeQuota: usdOf(before.data, site.quotaPerUnit) });
  }
  const after = await selfGetViaJar(site.baseUrl, jar, null, r.apiUser ?? login.apiUser ?? null);
  const data = r.data ?? {};
  return {
    success: true,
    // The login response's `checked_in` is the only honest success signal —
    // quota may legitimately not move if the bonus already landed today.
    checkedIn: Boolean(data['checked_in']),
    beforeQuota: usdOf(before.data, site.quotaPerUnit),
    afterQuota: usdOf(after.data, site.quotaPerUnit) ?? usdOf(data, site.quotaPerUnit),
    error: null,
    session: jarValue(jar, 'session'),
    accessToken: null,
    apiUser: r.apiUser ?? (typeof data['id'] !== 'undefined' ? String(data['id']) : null),
    username: typeof data['username'] === 'string' ? (data['username'] as string) : null,
    awarded: null,
  };
}

/** Do the daily check-in over HTTP. Never launches a browser. */
export async function checkIn(login: Login, site?: SiteInfo): Promise<Outcome> {
  const s = site ?? (await probe(login.baseUrl));
  let l = login;

  if (s.refreshPath && l.session && !l.accessToken) {
    // A JWT fork stores no session: what sits in the session field is a
    // refresh cookie, and it has to be spent for a Bearer <redacted> first.
    const { token, rotated, user } = await refreshAccess(l.baseUrl, l.session);
    if (token) {
      l = {
        ...l,
        accessToken: token,
        session: rotated ?? l.session, // rotated — must be persisted
        apiUser: l.apiUser ?? (user['id'] !== undefined ? String(user['id']) : null),
      };
    } else if (!l.username || !l.password) {
      return failOutcome('refresh 凭据已失效：到站点重新登录，复制新的 new_api_refresh cookie 再粘进来');
    }
  }

  if (s.turnstile) {
    // Turnstile tokens are minted in a browser; there is none here.
    return failOutcome('站点开启了 Turnstile 验证，Worker 版无法通过人机验证，该账号请用原版面板签到');
  }

  if (s.checkinPath) return checkInEndpoint(l, s);
  return checkInLoginBonus(l, s);
}

// ---------------------------------------------------------------------------
// Read-only helpers
// ---------------------------------------------------------------------------

/** GET a fork's check-in status route. Performs no check-in. */
export async function checkinStatus(
  baseUrl: string,
  path: string,
  quotaPerUnit = DEFAULT_QUOTA_PER_UNIT,
  creds: Creds = {},
): Promise<CheckinStatus> {
  const empty: CheckinStatus = { today: null, awardedToday: null, reward: null, total: null };
  try {
    const now = new Date();
    const month = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const r2 = await req(baseUrl, `${path}?month=${month}`, { method: 'GET' }, creds, null);
    const body = await bodyOf(r2);
    if (!body['success']) return empty;
    const data = body['data'];
    if (!data || typeof data !== 'object') return empty;
    const d = data as Record<string, unknown>;
    const stats = d['stats'] && typeof d['stats'] === 'object' ? (d['stats'] as Record<string, unknown>) : d;
    const stamp = `${month}-${String(now.getDate()).padStart(2, '0')}`;
    let awarded = stats['quota_awarded_today'];
    if (awarded === undefined || awarded === null) {
      const records = stats['records'];
      if (Array.isArray(records)) {
        for (const record of records) {
          if (
            record &&
            typeof record === 'object' &&
            String((record as Record<string, unknown>)['checkin_date'] ?? '').startsWith(stamp)
          ) {
            awarded = (record as Record<string, unknown>)['quota_awarded'];
            break;
          }
        }
      }
    }
    const total = stats['total_checkins'];
    // `reward_credits` is already a display amount, not raw quota units.
    const reward = d['reward_credits'];
    return {
      today: typeof stats['checked_in_today'] === 'boolean' ? (stats['checked_in_today'] as boolean) : null,
      awardedToday: usdRaw(awarded, quotaPerUnit),
      reward: typeof reward === 'number' ? reward : null,
      total: typeof total === 'number' ? total : null,
    };
  } catch {
    return empty; // its whole contract is "cannot say" on any trouble
  }
}

/** When the site's own quota log last recorded a check-in bonus. */
export async function lastCheckinAt(baseUrl: string, creds: Creds): Promise<number | null> {
  try {
    const response = await req(baseUrl, '/api/log/self?p=0&page_size=20&type=4', { method: 'GET' }, creds, null);
    const body = await bodyOf(response);
    if (!body['success']) return null;
    const data = body['data'];
    const items = data && typeof data === 'object' ? (data as Record<string, unknown>)['items'] : data;
    if (!Array.isArray(items)) return null;
    const stamps = items
      .filter(
        (it): it is Record<string, unknown> =>
          !!it && typeof it === 'object' && CHECKIN_LOG.test(String((it as Record<string, unknown>)['content'] ?? '')),
      )
      .map((it) => it['created_at'])
      .filter((s): s is number => typeof s === 'number');
    return stamps.length ? Math.max(...stamps) : null;
  } catch {
    return null; // its whole contract is "None when it cannot say"
  }
}

/**
 * Turn a session into a permanent username+password, so every later check-in
 * is pure HTTP. Only the password changes.
 */
export async function bootstrapPassword(
  baseUrl: string,
  session: string,
  opts: { apiUser?: string | null; password?: string | null } = {},
): Promise<{ username: string; password: string }> {
  const jar = new CookieJar();
  jar.set('session', session);
  const creds: Creds = { apiUser: opts.apiUser ?? null };
  const { data, error } = await selfGet(baseUrl, creds, jar);
  if (error || !data) throw new Error(`会话无效，无法设置密码: ${error ?? 'unknown'}`);
  const username = typeof data['username'] === 'string' ? (data['username'] as string) : '';
  const password =
    opts.password ?? Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(36)).join('').slice(0, 12);
  const response = await req(
    baseUrl,
    '/api/user/self',
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        display_name: (typeof data['display_name'] === 'string' && data['display_name']) || username,
      }),
    },
    creds,
    jar,
  );
  const body = await bodyOf(response);
  if (!body['success']) {
    let message = fail(body, response);
    if (message.includes('原密码')) message += '（该站点不允许给 OAuth 账号直接设置密码）';
    throw new Error(`设置密码失败: ${message}`);
  }
  return { username, password };
}

/** JSON-safe view of an Outcome: never hand a credential back to the caller. */
export function outcomeJson(o: Outcome): Record<string, unknown> {
  return {
    success: o.success,
    checked_in: o.checkedIn,
    before_quota: o.beforeQuota,
    after_quota: o.afterQuota,
    delta: outcomeDelta(o),
    gain: outcomeGain(o),
    awarded: o.awarded,
    error: o.error,
    api_user: o.apiUser,
    username: o.username,
  };
}

export function siteMechanismOf(site: SiteInfo): 'endpoint' | 'login_bonus' {
  return siteMechanism(site);
}

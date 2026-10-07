/**
 * Cron sweep: the Worker's replacement for panel/scheduler.py's in-process loop.
 *
 * Runs every 15 minutes (see wrangler.toml [triggers]). Each account is
 * eligible when:
 *   1. its `checkin_after` window has opened today (HH:MM in CHECKIN_TZ), and
 *   2. it has no successful run recorded today yet.
 *
 * Per-account failures never abort the sweep; consecutive failures are counted
 * in `failures` for backoff visibility (same column the original used).
 */

import {
  authenticate,
  checkIn,
  outcomeGain,
  probe,
  refreshAccess,
  type Login,
  type Outcome,
  type SiteInfo,
} from './newapi';
import {
  getCachedSite,
  listEnabled,
  persistRotated,
  recordResult,
  setCachedSite,
  type Account,
  type Env,
} from './store';

function tzParts(tz: string, d: Date): { date: string; hm: string } {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  const parts = Object.fromEntries(fmt.formatToParts(d).map((p) => [p.type, p.value]));
  return {
    date: `${parts['year']}-${parts['month']}-${parts['day']}`,
    hm: `${parts['hour'] === '24' ? '00' : parts['hour']}:${parts['minute']}`,
  };
}

function accountToLogin(a: Account): Login {
  return {
    baseUrl: a.baseUrl,
    loginMethod: a.loginMethod,
    username: a.username,
    password: a.password,
    accessToken: a.accessToken,
    session: a.session,
    apiUser: a.apiUser,
  };
}

async function siteFor(env: Env, baseUrl: string): Promise<SiteInfo> {
  const cached = await getCachedSite(env, baseUrl);
  if (cached) return cached;
  const fresh = await probe(baseUrl);
  await setCachedSite(env, fresh);
  return fresh;
}

export interface SweepItem {
  accountId: number;
  name: string;
  skipped: string | null;
  outcome: Outcome | null;
}

/**
 * Verify a credential the way the original did on save: a JWT fork's refresh
 * cookie is *spent* by the check, so verification persists the rotation in the
 * same breath. Returns {ok, reason, rotated}.
 */
export async function verifyCredential(
  env: Env,
  account: Account,
): Promise<{ ok: boolean; reason: string | null }> {
  try {
    const site = await siteFor(env, account.baseUrl);
    if (site.refreshPath && account.session && !account.accessToken) {
      const { token, rotated, user } = await refreshAccess(account.baseUrl, account.session);
      if (token) {
        await persistRotated(env, account.id, {
          session: rotated ?? account.session,
          accessToken: token,
          apiUser: account.apiUser ?? (user['id'] !== undefined ? String(user['id']) : null),
        });
        const { error } = await authenticate(account.baseUrl, {
          accessToken: token,
          apiUser: account.apiUser ?? (user['id'] !== undefined ? String(user['id']) : null),
        });
        return error ? { ok: false, reason: error } : { ok: true, reason: null };
      }
    }
    const { error } = await authenticate(account.baseUrl, {
      session: account.session,
      accessToken: account.accessToken,
      apiUser: account.apiUser,
    });
    return error ? { ok: false, reason: error } : { ok: true, reason: null };
  } catch (e) {
    return { ok: false, reason: `凭据没能验证：${e instanceof Error ? e.message : String(e)}` };
  }
}

/** Run one account's check-in now (manual trigger or sweep). Persists everything. */
export async function runCheckin(env: Env, account: Account): Promise<Outcome> {
  const site = await siteFor(env, account.baseUrl);
  const outcome = await checkIn(accountToLogin(account), site);
  await persistRotated(env, account.id, {
    session: outcome.session,
    accessToken: outcome.accessToken,
    apiUser: outcome.apiUser,
    username: outcome.username,
  });
  await recordResult(env, account.id, {
    success: outcome.success,
    checkedIn: outcome.checkedIn,
    quota: outcome.afterQuota ?? outcome.beforeQuota,
    error: outcome.error,
  });
  return outcome;
}

/** The cron entrypoint. Returns per-account results for logging. */
export async function sweep(env: Env): Promise<SweepItem[]> {
  const tz = env.CHECKIN_TZ || 'Asia/Shanghai';
  const { date: today, hm: nowHm } = tzParts(tz, new Date());
  const items: SweepItem[] = [];

  for (const account of await listEnabled(env)) {
    const item: SweepItem = { accountId: account.id, name: account.name, skipped: null, outcome: null };

    if (account.checkinAfter && nowHm < account.checkinAfter) {
      item.skipped = `站点每日 ${account.checkinAfter} 才开放（当前 ${nowHm}）`;
      items.push(item);
      continue;
    }
    if (account.lastRunAt && account.lastSuccess) {
      const { date: lastDate } = tzParts(tz, new Date(account.lastRunAt));
      if (lastDate === today) {
        item.skipped = '今天已签到成功';
        items.push(item);
        continue;
      }
    }

    try {
      item.outcome = await runCheckin(env, account);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      await recordResult(env, account.id, { success: false, checkedIn: null, quota: null, error });
      item.outcome = {
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
      };
    }
    items.push(item);
  }

  const done = items.filter((i) => i.outcome && !i.skipped);
  console.log(
    `[sweep] ${today} ${nowHm} (${tz}): ${done.length} ran, ${items.length - done.length} skipped, ` +
      done
        .map((i) => `${i.name}: ${i.outcome!.success ? `ok gain=${outcomeGain(i.outcome!) ?? '?'}` : `FAIL ${i.outcome!.error}`}`)
        .join('; '),
  );
  return items;
}

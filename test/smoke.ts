/* Smoke test for pure logic: credential parsing, crypto round-trip, outcome math. */
import assert from 'node:assert/strict';
import { credentialsFromPaste, parseSession, outcomeDelta, outcomeGain } from '../src/newapi';
import { encryptSecret, decryptSecret } from '../src/crypto';

// parseSession: bare value
assert.equal(parseSession('abc123'), 'abc123');
// parseSession: header shape
assert.equal(parseSession('session=tok456; other=w'), 'tok456');
// parseSession: JSON dict
assert.equal(parseSession('{"session":"s1","_ga":"x"}'), 's1');
// parseSession: exported cookie list prefers session over refresh
assert.equal(
  parseSession(JSON.stringify([{ name: 'new_api_refresh', value: 'r1' }, { name: 'session', value: 's2' }])),
  's2',
);
// parseSession: empty
assert.equal(parseSession(''), null);

// credentialsFromPaste: strict — jar without credential cookies raises
assert.throws(() => credentialsFromPaste('{"_ga":"x"}'), /只找到/);
// credentialsFromPaste: ok
const c = credentialsFromPaste('session=tok999; Path=/');
assert.equal(c[0]!.value, 'tok999');
assert.equal(c[0]!.cookieName, 'session');

// outcome math
assert.equal(outcomeDelta({ success: true, checkedIn: true, beforeQuota: 10, afterQuota: 12.5, error: null, session: null, accessToken: null, apiUser: null, username: null, awarded: null }), 2.5);
assert.equal(outcomeGain({ success: true, checkedIn: true, beforeQuota: 10, afterQuota: 12.5, error: null, session: null, accessToken: null, apiUser: null, username: null, awarded: 3 }), 3);

// crypto round-trip (WebCrypto in node 20+)
const key = Buffer.from('0123456789abcdef0123456789abcdef').toString('base64');
const stored = await encryptSecret(key, 'sk-secret-value');
assert.ok(stored.includes('.'));
assert.equal(await decryptSecret(key, stored), 'sk-secret-value');

console.log('smoke OK');

// Nominee side in an iPhone-sized browser: claim, interview, release, then open the vault with two of three answers
import { chromium, devices } from 'playwright'; import fs from 'fs'; import vm from 'vm'; import crypto from 'crypto';
const B = process.env.B || 'http://localhost:8787', ADM = process.env.ADM || 'admin-dev-token', OUT = process.env.OUT || 'shots';

// Production guard: refuse to run tests against non-localhost unless explicitly allowed
const u = new URL(B);
if (!['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && process.env.ALLOW_LIVE !== 'yes-i-mean-production') {
  console.error(`HARD RULE: Tests must not run against ${B}. Only localhost/127.0.0.1/[::1] are allowed, or set ALLOW_LIVE=yes-i-mean-production.`);
  process.exit(1);
}

const ctxv = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array }; vm.createContext(ctxv);
vm.runInContext(fs.readFileSync(new URL('../public/crypto.js', import.meta.url), 'utf8') + ';this.SMS=SMS;', ctxv); const { SMS } = ctxv;
let fails = 0; const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
const call = async (p, { method = 'GET', body, token } = {}) => { const r = await fetch(B + p, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }); return { s: r.status, d: await r.json().catch(() => ({})) }; };
function totp(secret) { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of secret) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4); const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0'); }
const inv = 'NUI' + Date.now(); await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: inv, max_uses: 1 } });
const owner = `qa+nui${Date.now()}@example.com`, nomEmail = `qa+nuinom${Date.now()}@example.com`, salt = SMS.b64(SMS.rand(16)), k = await SMS.deriveFromPassword('a long passphrase for testing', salt);
let r = await call('/api/register', { method: 'POST', body: { email: owner, name: 'Olivia Owner', authKey: k.authKey, kdfSalt: salt, inviteCode: inv } });
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); const tok = r.d.token;
const v = await SMS.createVault(k.ownerKey, { letter: 'Dear Nadia, the deeds are with Sarah Jones.', items: [{ title: 'Email', body: 'olivia@example.com / horse battery' }] });
await call('/api/me/vault', { method: 'POST', token: tok, body: v.upload });
await call('/api/me/policy', { method: 'POST', token: tok, body: { proof_required: 'none', checkin_days: 90, grace_weeks: 2, veto_days: 3 } });
const keys = await SMS.buildNomineeKeys(v.K, (await call('/api/me/share', { token: tok })).d.serverShare,
  [{ q: 'Where did we spend every summer as children?', answer: 'Saint-Tropez' }, { q: "What was Grandpa's dog called?", answer: 'Biscuit' }, { q: 'What did Mum always burn?', answer: 'The toast' }]);
r = await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'Nadia Nominee', email: nomEmail, relationship: 'sister', keys } });
ok(r.s === 200 && (await call('/api/me', { token: tok })).d.hasRelease === false, 'nominee added with their questions; we never held a copy');

const browser = await chromium.launch(); const page = await (await browser.newContext({ ...devices['iPhone 13'] })).newPage(); const errs = []; page.on('pageerror', e => errs.push(e.message));
await page.goto(B + '/claim'); await page.fill('#cName', 'Nadia Nominee'); await page.fill('#cEmail', nomEmail); await page.click('#f1 button'); await page.waitForSelector('#s2:not(.hide)');
const ev = (await call('/api/admin/events', { token: ADM })).d.find(e => e.detail.includes('verification code') && e.detail.includes(nomEmail));
await page.fill('#cCode', JSON.parse(ev.detail).html.match(/<b>(\d{6})<\/b>/)[1]); await page.click('#f2 button'); await page.waitForSelector('#sFind:not(.hide)');
await page.fill('#oEmail', owner); await page.click('#fFind button'); await page.waitForSelector('#s3:not(.hide)');
const live = B.startsWith('https');
const lines = ['Olivia died suddenly on 9 October 2026 at home in London. I am her sister Nadia.', 'She had a stroke in the morning; the ambulance took her to Chelsea and Westminster Hospital where she died.', 'Her husband Tom and her solicitor Sarah Jones both know. The funeral is on 20 October.', 'She told me about Save My Secrets last year and it is in her letter of wishes.', 'She was 56, born in 1970.', 'Nothing else to add.', 'Yes.', 'Thank you.', 'Ok.', 'Ok.', 'Ok.', 'Ok.'];
for (const t of lines) { if (!(await page.isVisible('#s3'))) break; const n = (await page.$$('#chat .bubble')).length; await page.fill('#cMsg', t); await page.click('#f3 button');
  for (let w = 0; w < 120 && (await page.$$('#chat .bubble')).length < n + 2 && await page.isVisible('#s3'); w++) await page.waitForTimeout(500); }
await page.waitForTimeout(2000); ok(await page.isVisible('#s5'), 'interview done, request being checked');
const cid = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.owner_email === owner).id;
await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId: cid, decision: 'approve' } });
await page.click('#btnCheck'); await page.waitForTimeout(1500); const s5 = await page.textContent('#s5msg'); ok(s5.includes('final check'), 'nominee told about the final check');
const end = Number((await call('/api/admin/claims', { token: ADM })).d.find(c => c.id === cid) && Date.now() + 40 * 86400000);
await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: end, emails: [owner] } });
await page.click('#btnCheck'); await page.waitForSelector('#s6:not(.hide)'); await page.screenshot({ path: `${OUT}/n-1-questions.png`, fullPage: true });
ok((await page.textContent('#qList')).includes("Grandpa's dog"), 'questions shown to the nominee');
await page.fill('#qa0', 'Nice'); await page.fill('#qa1', 'Rex'); await page.fill('#qa2', 'Cake'); await page.click('#btnOpen'); await page.waitForTimeout(4000);
ok((await page.textContent('#flash')).includes('did not open'), 'wrong answers refused with a clear message');
await page.fill('#qa0', 'saint tropez'); await page.fill('#qa1', 'no idea'); await page.fill('#qa2', 'toast'); await page.click('#btnOpen');
await page.waitForSelector('#vaultOut .item', { timeout: 30000 }); await page.screenshot({ path: `${OUT}/n-2-opened.png`, fullPage: true });
ok((await page.textContent('#vaultOut')).includes('the deeds are with Sarah Jones'), 'vault opened with two of three answers, on the device');
ok((await page.textContent('#vaultOut')).includes('A letter for you'), 'an existing letter is still shown to the nominee');
console.log('page errors:', errs.length ? errs : 'none'); console.log('owner:', owner);
await browser.close(); console.log(fails ? `${fails} FAILED` : 'ALL PASSED'); process.exit(fails ? 1 : 0);

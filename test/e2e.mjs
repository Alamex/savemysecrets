import fs from 'fs'; import vm from 'vm'; import crypto from 'crypto';
const B = 'http://localhost:8787', ADM = 'admin-dev-token', DAY = 86400000;
const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array, JSON, document: undefined };
vm.createContext(ctx); vm.runInContext(fs.readFileSync(new URL('../public/crypto.js', import.meta.url), 'utf8') + ';this.SMS=SMS;', ctx);
const { SMS } = ctx;
let fails = 0; const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
async function call(p, { method = 'GET', body, token, raw } = {}) {
  const r = await fetch(B + p, { method, redirect: 'manual', headers: { ...(body && !raw ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: raw || (body ? JSON.stringify(body) : undefined) });
  const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = t; } return { s: r.status, d, h: r.headers };
}
function totp(secret) { // RFC 6238 in node
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of secret) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
  const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}
const email = `neil+${Date.now()}@example.com`, pw = 'correct horse battery staple';

ok((await call('/api/waitlist', { method: 'POST', body: { email: 'w' + Date.now() + '@x.com', source: 'conf' } })).s === 200, 'waitlist');
ok((await call('/api/waitlist', { method: 'POST', body: { email: 'nope' } })).s === 400, 'waitlist rejects bad email');
ok((await call('/api/subscribe', { method: 'POST', body: { email: 's' + Date.now() + '@x.com', source: 'holding-page' } })).s === 200, 'old /api/subscribe still works');
ok((await call('/no-such-page')).s === 301, 'unknown URL 301s to home');

ok((await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: 'test-conf', label: 'test', max_uses: 1000 } })).s === 200, 'invite created');
await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: 'ONEUSE' + Date.now(), max_uses: 1 } });
ok((await call('/api/invite/check', { method: 'POST', body: { code: 'nope' } })).s === 400, 'bad invite rejected');
ok((await call('/api/invite/check', { method: 'POST', body: { code: 'test conf' } })).s === 200, 'invite check normalises spaces/case');
const kdfSalt = SMS.b64(SMS.rand(16)); const k = await SMS.deriveFromPassword(pw, kdfSalt);
ok((await call('/api/register', { method: 'POST', body: { email: 'noinv' + Date.now() + '@x.com', name: 'X', authKey: k.authKey, kdfSalt } })).s === 403, 'register without invite refused');
const one = 'ONE' + Date.now(); await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: one, max_uses: 1 } });
ok((await call('/api/register', { method: 'POST', body: { email: 'a' + Date.now() + '@x.com', name: 'A', authKey: k.authKey, kdfSalt, inviteCode: one } })).s === 200, 'single-use invite works once');
ok((await call('/api/register', { method: 'POST', body: { email: 'b' + Date.now() + '@x.com', name: 'B', authKey: k.authKey, kdfSalt, inviteCode: one } })).s === 403, 'single-use invite refused second time');
let r = await call('/api/register', { method: 'POST', body: { email, name: 'Test Owner', phone: '+971500000000', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
ok(r.s === 200 && r.d.totpSecret, 'register');
const secret = r.d.totpSecret;
ok((await call('/api/me', { token: r.d.token })).s === 401, 'enrol session cannot reach vault');
ok((await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: '000000' } })).s === 400, 'wrong TOTP rejected');
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(secret) } });
ok(r.s === 200, '2FA enabled'); let tok = r.d.token;

const contents = { letter: 'Dear family, love you.', items: [{ type: 'Seed phrase / wallet', title: 'Cold wallet', body: 'abandon ability able about above absent absorb abstract absurd abuse access accident' }] };
const v = await SMS.createVault(k.ownerKey, contents, 'sovereign');
ok(/^[A-Z2-9]{4}(-[A-Z2-9]{4}){7}$/.test(v.legacyCode), 'legacy code format ' + v.legacyCode);
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: v.upload })).s === 200, 'vault sealed');
// server must not be able to decrypt with S alone
let serverAlone = true; try { await SMS.unlockRelease(v.upload.serverShare, v.upload.wrappedRelease, SMS.codeEncode(new Uint8Array(20)), 'sovereign'); } catch { serverAlone = false; }
ok(!serverAlone, 'server share alone cannot open vault');

ok((await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'Nom Inee', email: 'nominee@example.com', phone: '+447700900000', relationship: 'wife' } })).s === 200, 'nominee added');
ok((await call('/api/me/policy', { method: 'POST', token: tok, body: { checkin_days: 90, grace_weeks: 6, proof_required: 'death_certificate', veto_days: 7 } })).s === 200, 'policy saved');

// login
const pre = await call('/api/prelogin', { method: 'POST', body: { email } }); ok(pre.d.kdfSalt === kdfSalt, 'prelogin salt');
ok((await call('/api/login', { method: 'POST', body: { email, authKey: 'wrong', code: totp(secret) } })).s === 401, 'bad password rejected');
ok((await call('/api/login', { method: 'POST', body: { email, authKey: k.authKey, code: '123456' } })).s === 401, 'bad 2FA rejected');
r = await call('/api/login', { method: 'POST', body: { email, authKey: k.authKey, code: totp(secret) } }); ok(r.s === 200, 'login'); tok = r.d.token;
const me = (await call('/api/me', { token: tok })).d;
const K = await SMS.unlockOwner(k.ownerKey, me.wrappedOwner); const back = await SMS.decVault(K, me.vault);
ok(back.items[0].body === contents.items[0].body, 'owner decrypts vault');

// owner backup download has been removed
ok((await call('/api/me/kit', { token: tok })).s === 404, 'backup download removed');

// escalation timeline
const t0 = Date.now(); const esc = async at => (await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at } })).d.filter(x => x[0] === email).map(x => x[1]);
ok((await esc(t0 + 10 * DAY)).length === 0, 'nothing before due');
ok((await esc(t0 + 91 * DAY))[0] === 'first reminder', 'first reminder at 91d');
const steps = [];
for (let w = 1; w <= 6; w++) steps.push(...await esc(t0 + 91 * DAY + w * 7 * DAY + 1000));
console.log('   timeline:', steps.join(' | '));
ok(steps.at(-1).startsWith('nominees contacted'), 'nominees contacted after 6 weeks');
ok((await call('/api/me', { token: tok })).d.state === 'nominees_contacted', 'state nominees_contacted');

// claim by an impostor email: generic response, claim flagged as non-nominee
r = await call('/api/claim/start', { method: 'POST', body: { u: me.nominees[0].user_id, name: 'Nom Inee', email: 'nominee@example.com' } });
ok(r.s === 200 && r.d.claimId, 'claim started'); const claimId = r.d.claimId;
const ev = (await call('/api/admin/events', { token: ADM })).d.find(e => e.kind.startsWith('email') && e.detail.includes('verification code') && e.detail.includes('nominee@example.com'));
const otp = JSON.parse(ev.detail).html.match(/<b>(\d{6})<\/b>/)[1];
ok((await call('/api/claim/verify', { method: 'POST', body: { claimId, code: '000000' } })).s === 401, 'wrong OTP rejected');
r = await call('/api/claim/verify', { method: 'POST', body: { claimId, code: otp } }); ok(r.s === 200, 'OTP ok'); const ct = r.d.token;
let st;
for (const msg of ['I am his wife. He died of a heart attack.', 'Last Tuesday in Dubai, at Mediclinic.', 'His brother and our solicitor know.', 'Yes I have the certificate now.']) {
  r = await call('/api/claim/message', { method: 'POST', token: ct, body: { text: msg } }); st = r.d; if (st.done) break;
}
ok(st.done && st.status === 'awaiting_document', 'interview complete, awaiting certificate');
ok((await call('/api/claim/status', { token: ct })).d.package === undefined, 'no package before release');
const fd = new FormData(); fd.append('file', new Blob([Buffer.from('%PDF-1.4 fake')], { type: 'application/pdf' }), 'cert.pdf');
r = await fetch(B + '/api/claim/document', { method: 'POST', headers: { authorization: 'Bearer ' + ct }, body: fd }); ok(r.status === 200, 'certificate uploaded');
ok((await call('/api/admin/claims', { token: 'nope' })).s === 401, 'admin requires token');
const cl = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.id === claimId); ok(cl.status === 'review' && cl.doc_key, 'claim in review with doc');
ok((await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId, decision: 'approve', note: 'test' } })).s === 200, 'approved');
const vetoEnd = (await call('/api/me', { token: tok })).d; ok(vetoEnd.state === 'veto_window', 'veto window started');
ok((await esc(Date.now() + 1000))[0] === 'veto alarm', 'veto alarm sent');
ok((await esc(Date.now() + 8 * DAY))[0] === 'released', 'released after veto window');
const pkg = (await call('/api/claim/status', { token: ct })).d.package;
ok(pkg && pkg.serverShare, 'package delivered to nominee');
let wrongCodeOpens = true; try { await SMS.unlockRelease(pkg.serverShare, pkg.wrappedRelease, SMS.codeEncode(SMS.rand(20)), pkg.releaseMode); } catch { wrongCodeOpens = false; }
ok(!wrongCodeOpens, 'wrong legacy code fails');
const Kn = await SMS.unlockRelease(pkg.serverShare, pkg.wrappedRelease, v.legacyCode.toLowerCase().replace(/-/g, ' '), pkg.releaseMode);
ok((await SMS.decVault(Kn, pkg.vault)).items[0].title === 'Cold wallet', 'nominee opens vault with legacy code (lower case, spaces)');

// Scenario 2: owner vetoes by email link during veto window
const email2 = `veto+${Date.now()}@example.com`; const k2 = await SMS.deriveFromPassword(pw, kdfSalt);
r = await call('/api/register', { method: 'POST', body: { email: email2, name: 'Alive Owner', authKey: k2.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); const tok2 = r.d.token;
await call('/api/me/vault', { method: 'POST', token: tok2, body: (await SMS.createVault(k2.ownerKey, { items: [] }, 'standard')).upload });
await call('/api/me/policy', { method: 'POST', token: tok2, body: { proof_required: 'none', checkin_days: 30, grace_weeks: 2, veto_days: 7 } });
await call('/api/me/nominees', { method: 'POST', token: tok2, body: { name: 'Bro', email: 'bro@example.com' } });
const me2 = (await call('/api/me', { token: tok2 })).d; const uid2 = me2.nominees[0].user_id;
r = await call('/api/claim/start', { method: 'POST', body: { u: uid2, name: 'Bro', email: 'bro@example.com' } }); const c2 = r.d.claimId;
const ev2 = (await call('/api/admin/events', { token: ADM })).d.find(e => e.user_id === uid2 && e.detail.includes('verification code'));
r = await call('/api/claim/verify', { method: 'POST', body: { claimId: c2, code: JSON.parse(ev2.detail).html.match(/<b>(\d{6})<\/b>/)[1] } }); const ct2 = r.d.token;
for (let i = 0; i < 3; i++) st = (await call('/api/claim/message', { method: 'POST', token: ct2, body: { text: 'answer ' + i } })).d;
ok(st.status === 'review', 'proof=none goes straight to review');
await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId: c2, decision: 'approve' } });
const alarm = (await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: Date.now() + 1000 } })).d;
const evs = (await call('/api/admin/events', { token: ADM })).d.filter(e => e.user_id === uid2 && e.detail.includes('/api/checkin?'));
const link = JSON.parse(evs[0].detail).html.match(/href="([^"]+)"/)[1].replace(/&amp;/g, '&');
r = await call(link.replace(/^https?:\/\/[^/]+/, '')); ok(r.s === 302, 'email check-in link works');
ok((await call('/api/me', { token: tok2 })).d.state === 'active', 'owner back to active');
ok((await call('/api/claim/status', { token: ct2 })).d.status === 'vetoed', 'claim vetoed by owner check-in');
r = await call(link.replace(/^https?:\/\/[^/]+/, '').replace(/s=[0-9a-f]+/, 's=deadbeef')); ok(r.s === 400, 'tampered check-in link rejected');

console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); process.exit(fails ? 1 : 0);

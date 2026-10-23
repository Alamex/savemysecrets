import fs from 'fs'; import vm from 'vm'; import crypto from 'crypto'; import { execFileSync } from 'child_process';
const B = process.env.B || 'http://localhost:8787', ADM = process.env.ADM || 'admin-dev-token', DAY = 86400000;

// Production guard: refuse to run tests against non-localhost unless explicitly allowed
const u = new URL(B);
if (!['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && process.env.ALLOW_LIVE !== 'yes-i-mean-production') {
  console.error(`HARD RULE: Tests must not run against ${B}. Only localhost/127.0.0.1/[::1] are allowed, or set ALLOW_LIVE=yes-i-mean-production.`);
  process.exit(1);
}

const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array, JSON, document: undefined };
vm.createContext(ctx); vm.runInContext(fs.readFileSync(new URL('../public/crypto.js', import.meta.url), 'utf8') + ';this.SMS=SMS;', ctx);
const { SMS } = ctx;
let fails = 0, r0; const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
// Registrations and claimant code requests are rate limited per client IP (worker.js reads CF-Connecting-IP).
// Give each such request its own test IP so the suite doesn't trip the 10/hour limits; per-email limits still apply.
let ipSeq = 0; const ipFor = p => ['/api/register', '/api/claimant/start', '/api/invite/check'].includes(p) ? { 'cf-connecting-ip': `198.51.100.${(++ipSeq % 250) + 1}` } : {};
async function call(p, { method = 'GET', body, token, raw } = {}) {
  const r = await fetch(B + p, { method, redirect: 'manual', headers: { ...ipFor(p), ...(body && !raw ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: raw || (body ? JSON.stringify(body) : undefined) });
  const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = t; } return { s: r.status, d, h: r.headers };
}
function totp(secret) { // RFC 6238 in node
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of secret) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
  const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}
// First emails carry a tip to add our From address (MAIL_FROM, default hello@savemysecrets.com) to contacts; later ones don't
const TIP = 'Tip: add hello@savemysecrets.com to your contacts so our emails never end up in spam.';
const mailTo = async (to, subj) => (await call('/api/admin/events', { token: ADM })).d.find(e => e.kind.startsWith('email') && e.detail.includes(to) && e.detail.includes(subj));
const hasTip = async (to, subj) => { const e = await mailTo(to, subj); return !!e && e.detail.includes(TIP); };
const otpFor = async to => { const e = (await call('/api/admin/events', { token: ADM })).d.find(e => e.kind.startsWith('email') && e.detail.includes('verification code') && e.detail.includes(to)); return JSON.parse(e.detail).html.match(/<b>(\d{6})<\/b>/)[1]; };
async function claimant(name, mail) {
  const s1 = await call('/api/claimant/start', { method: 'POST', body: { name, email: mail } });
  const v = await call('/api/claimant/verify', { method: 'POST', body: { claimantId: s1.d.claimantId, code: await otpFor(mail) } });
  return v.d.token;
}
const email = `neil+${Date.now()}@example.com`, pw = 'correct horse battery staple';
// Every nominee is added together with their three questions (built in the browser from the vault key and our share)
const QS = [{ q: 'First street?', answer: 'Elm Road' }, { q: 'Old dog?', answer: 'Rufus' }, { q: 'Wedding town?', answer: 'Hove' }];
async function addNom(tok, K, body, qs = QS) {
  const keys = await SMS.buildNomineeKeys(K, (await call('/api/me/share', { token: tok })).d.serverShare, qs);
  return call('/api/me/nominees', { method: 'POST', token: tok, body: { ...body, keys } });
}
// Vaults sealed before questions were required can't be made through the API any more, so the local test database is
// given one directly: a standard release copy plus a nominee without questions, as on production. Local D1 only.
const LOCAL = ['localhost', '127.0.0.1', '[::1]'].includes(new URL(B).hostname);
const d1 = sql => { if (!LOCAL) throw new Error('legacy seeding is local only');
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'savemysecrets', '--local', '--command', sql], { cwd: new URL('..', import.meta.url).pathname, stdio: 'pipe' }); };
async function makeLegacy(ownerEmail, tok, K, nominees) {
  const S = (await call('/api/me/share', { token: tok })).d.serverShare;
  const wr = await SMS.seal(await SMS.releaseKey(SMS.unb64(S), new Uint8Array(20)), K);
  d1(`UPDATE users SET wrapped_release='${wr}', release_mode='standard' WHERE email='${ownerEmail}'`);
  for (const n of nominees) d1(`INSERT INTO nominees (id,user_id,name,email,relationship,notify_early,created_at) VALUES ('${n.id}',(SELECT id FROM users WHERE email='${ownerEmail}'),'${n.name}','${n.email}','${n.rel || ''}',0,${Date.now()})`);
}

const wlEmail = 'w' + Date.now() + '@example.com';
ok((await call('/api/waitlist', { method: 'POST', body: { email: wlEmail, source: 'conf' } })).s === 200, 'waitlist');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind.startsWith('email') && e.detail.includes(wlEmail) && e.detail.includes('access request')), 'waitlist confirmation email sent');
ok((await call('/api/waitlist', { method: 'POST', body: { email: 'nope' } })).s === 400, 'waitlist rejects bad email');
ok((await call('/api/subscribe', { method: 'POST', body: { email: 's' + Date.now() + '@x.com', source: 'holding-page' } })).s === 200, 'old /api/subscribe still works');

// Approval system: unique single-use codes
const approveEmail1 = 'approve1+' + Date.now() + '@x.com', approveEmail2 = 'approve2+' + Date.now() + '@x.com';
ok((await call('/api/waitlist', { method: 'POST', body: { email: approveEmail1, source: 'test' } })).s === 200, 'first approval candidate on waitlist');
ok((await call('/api/waitlist', { method: 'POST', body: { email: approveEmail2, source: 'test' } })).s === 200, 'second approval candidate on waitlist');
const approveRes = await call('/api/admin/waitlist/invite', { method: 'POST', token: ADM, body: { emails: [approveEmail1, approveEmail2] } });
ok(approveRes.s === 200 && approveRes.d.sent === 2, 'admin approved two people');
const events = (await call('/api/admin/events', { token: ADM })).d;
ok(await hasTip(wlEmail, 'access request received') && await hasTip(approveEmail1, 'approved for Save My Secrets'), 'first emails: access request and approval carry the contacts tip');
const email1Event = events.find(e => e.kind.startsWith('email') && e.detail.includes(approveEmail1) && e.detail.includes('approved'));
const email2Event = events.find(e => e.kind.startsWith('email') && e.detail.includes(approveEmail2) && e.detail.includes('approved'));
const code1 = email1Event ? JSON.parse(email1Event.detail).html.match(/code=([A-Z0-9]{6})/)[1] : null;
const code2 = email2Event ? JSON.parse(email2Event.detail).html.match(/code=([A-Z0-9]{6})/)[1] : null;
ok(code1 && code2 && code1 !== code2, 'each person gets a unique code');
ok((await call('/api/invite/check', { method: 'POST', body: { code: code1 } })).s === 200, 'first code valid');
ok((await call('/api/invite/check', { method: 'POST', body: { code: code2 } })).s === 200, 'second code valid');
// Use code1 to register
const kdfSalt1 = SMS.b64(SMS.rand(16));
const k1 = await SMS.deriveFromPassword('password for approval test 1', kdfSalt1);
const reg1 = await call('/api/register', { method: 'POST', body: { email: approveEmail1, name: 'Approval Test 1', authKey: k1.authKey, kdfSalt: kdfSalt1, inviteCode: code1 } });
ok(reg1.s === 200, 'registration with first code succeeds');
ok((await call('/api/invite/check', { method: 'POST', body: { code: code1 } })).s === 400, 'first code refused after use');
// code2 still works for its intended user
const kdfSalt2 = SMS.b64(SMS.rand(16));
const k2Approval = await SMS.deriveFromPassword('password for approval test 2', kdfSalt2);
const reg2 = await call('/api/register', { method: 'POST', body: { email: approveEmail2, name: 'Approval Test 2', authKey: k2Approval.authKey, kdfSalt: kdfSalt2, inviteCode: code2 } });
ok(reg2.s === 200, 'registration with second code succeeds');
ok((await call('/api/invite/check', { method: 'POST', body: { code: code2 } })).s === 400, 'second code refused after use');

ok((await call('/no-such-page')).s === 404, 'unknown URL returns 404');
for (const pg of ['/privacy', '/terms', '/claim', '/preview']) ok((await call(pg)).s === 200, pg + ' serves');
ok((await call('/')).h.get('content-security-policy')?.includes("frame-ancestors 'none'"), 'CSP header set');

ok((await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: 'test-conf', label: 'test', max_uses: 1000 } })).s === 200, 'manual invite code created');
ok((await call('/api/feedback', { method: 'POST', body: { text: 'The rehearse tab is great', page: '/app' } })).s === 200, 'feedback accepted');
ok((await call('/api/admin/feedback', { token: ADM })).d.some(f => f.text === 'The rehearse tab is great'), 'feedback visible in admin');
await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: 'ONEUSE' + Date.now(), max_uses: 1 } });
ok((await call('/api/invite/check', { method: 'POST', body: { code: 'nope' } })).s === 400, 'bad invite rejected');
ok((await call('/api/invite/check', { method: 'POST', body: { code: 'test conf' } })).s === 200, 'manual invite check normalises spaces/case');
const kdfSalt = SMS.b64(SMS.rand(16)); const k = await SMS.deriveFromPassword(pw, kdfSalt);
ok((await call('/api/register', { method: 'POST', body: { email: 'noinv' + Date.now() + '@x.com', name: 'X', authKey: k.authKey, kdfSalt } })).s === 403, 'register without invite refused');
const one = 'ONE' + Date.now(); await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: one, max_uses: 1 } });
ok((await call('/api/register', { method: 'POST', body: { email: 'a' + Date.now() + '@x.com', name: 'A', authKey: k.authKey, kdfSalt, inviteCode: one } })).s === 200, 'manual single-use invite works once');
ok((await call('/api/register', { method: 'POST', body: { email: 'b' + Date.now() + '@x.com', name: 'B', authKey: k.authKey, kdfSalt, inviteCode: one } })).s === 403, 'manual single-use invite refused second time');
let r = await call('/api/register', { method: 'POST', body: { email, name: 'Test Owner', phone: '+971500000000', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
ok(r.s === 200 && r.d.totpSecret, 'register');
const secret = r.d.totpSecret;
const LOGO_PARAM = '&image=' + encodeURIComponent('https://savemysecrets.com/totp-logo.png');
ok(typeof r.d.otpauth === 'string' && r.d.otpauth.startsWith('otpauth://totp/Save%20My%20Secrets:') && r.d.otpauth.includes('issuer=Save%20My%20Secrets') && r.d.otpauth.includes('secret=' + secret) && r.d.otpauth.endsWith(LOGO_PARAM), 'otpauth URI keeps issuer and label and includes the logo image param');
ok((await call('/api/me', { token: r.d.token })).s === 401, 'enrol session cannot reach vault');
ok((await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: '000000' } })).s === 400, 'wrong TOTP rejected');
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(secret) } });
ok(r.s === 200, '2FA enabled'); let tok = r.d.token;
ok(Array.isArray(r.d.recoveryCodes) && r.d.recoveryCodes.length === 10, '10 recovery codes issued');

const contents = { letter: 'Dear family, love you.', items: [{ type: 'Seed phrase / wallet', title: 'Cold wallet', body: 'abandon ability able about above absent absorb abstract absurd abuse access accident' }] };
const v = await SMS.createVault(k.ownerKey, contents);
ok(v.upload.releaseMode === 'questions' && !('wrappedRelease' in v.upload) && !('legacyCode' in v), 'new vaults make no release copy of the key, and no printed code');
ok((await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'Too Early', email: 'early@example.com', keys: {} } })).s === 400, 'no nominees before the vault is sealed');
// A copy of the key that our share alone opens is refused, whatever mode the request names
const stdCopy = await SMS.seal(await SMS.releaseKey(SMS.unb64(v.upload.serverShare), new Uint8Array(20)), v.K);
for (const mode of ['standard', 'questions', 'sovereign', undefined]) ok((await call('/api/me/vault', { method: 'POST', token: tok, body: { ...v.upload, wrappedRelease: stdCopy, releaseMode: mode } })).s === 400, `new vault: wrapped_release upload refused (mode ${mode})`);
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: { ...v.upload, releaseMode: 'standard' } })).s === 400, 'sealing in standard mode refused');
ok(!(await call('/api/me', { token: tok })).d.hasRelease && !(await call('/api/me', { token: tok })).d.wrappedOwner, 'rejected seals stored nothing');
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: v.upload })).s === 200, 'vault sealed');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.detail.includes(email) && e.detail.includes('Your vault is set up')), 'welcome email after sealing');
ok(await hasTip(email, 'Your vault is set up'), 'welcome email carries the contacts tip');
{ const m1 = (await call('/api/me', { token: tok })).d; ok(m1.releaseMode === 'questions' && m1.hasRelease === false, 'new vault: no release copy stored, questions-only mode'); }
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: { ...v.upload, wrappedRelease: stdCopy } })).s === 400, 'sealed vault: wrapped_release upload still refused');
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: (await SMS.createVault(k.ownerKey, {})).upload })).s === 409, 'our share cannot be replaced once sealed');
ok((await call('/api/me', { token: tok })).d.hasRelease === false, 'still no release copy');
ok((await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'Nom Inee', email: 'nominee@example.com', phone: '+447700900000', relationship: 'wife' } })).s === 400, 'nominee without questions refused');
ok((await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'Nom Inee', email: 'nominee@example.com', keys: { questions: ['a', 'b'], salts: [], wraps: {}, verifiers: {} } } })).s === 400, 'nominee with malformed questions refused');
ok((await call('/api/me', { token: tok })).d.nominees.length === 0, 'refused nominees stored nothing');
// This owner's vault predates required questions: seed the old standard copy and a nominee with no questions (local D1)
await makeLegacy(email, tok, v.K, [{ id: 'legacynom1', name: 'Nom Inee', email: 'nominee@example.com', rel: 'wife' }]);
{ const m1 = (await call('/api/me', { token: tok })).d; ok(m1.hasRelease === true && m1.releaseMode === 'standard' && m1.nominees.length === 1 && !m1.nominees[0].hasQuestions, 'existing standard vault: copy held, nominee not set up'); }
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: { vault: v.upload.vault, wrappedOwner: v.upload.wrappedOwner } })).s === 200 && (await call('/api/me', { token: tok })).d.hasRelease === true, 'existing standard vault: saving contents keeps it working');
ok((await addNom(tok, v.K, { name: 'No Plus', email: 'noplus@example.com', phone: '07700 900000' })).s === 400, 'phone without country code refused');
ok((await call('/api/me/policy', { method: 'POST', token: tok, body: { phone: '00971 50 123 4567' } })).s === 200 && (await call('/api/me', { token: tok })).d.phone === '+971501234567', 'phone tidied to +971501234567');
await call('/api/me/policy', { method: 'POST', token: tok, body: { checkin_days: 90 } }); ok((await call('/api/me', { token: tok })).d.phone === '+971501234567', 'rules saved without a phone keep the stored mobile');
await call('/api/me/policy', { method: 'POST', token: tok, body: { checkin_days: 90, phone: '' } }); ok((await call('/api/me', { token: tok })).d.phone === null, 'rules saved with an empty mobile remove it');
await call('/api/me/policy', { method: 'POST', token: tok, body: { checkin_days: 90, phone: '+971 50 123 4567' } });
ok((await call('/api/me/policy', { method: 'POST', token: tok, body: { checkin_days: 90, grace_weeks: 6, proof_required: 'death_certificate', veto_days: 7 } })).s === 200, 'policy saved');
// Rehearsal: owner plays their nominee; nothing stored, nobody alerted, state unchanged
const evBefore = (await call('/api/admin/events', { token: ADM })).d[0].id;
let rh = await call('/api/me/rehearse', { method: 'POST', token: tok, body: { messages: [] } }); ok(rh.s === 200 && rh.d.reply.includes('what has happened'), 'rehearsal opens with the real first question');
const rmsgs = [];
for (const t of ['I am his wife, he died last week.', 'At home in Dubai on 6 October 2026.', 'His brother and our solicitor know.', 'I have the death certificate.', 'Nothing else.', 'Yes.', 'Thank you.', 'Ok.', 'Fine.', 'Done.', 'Yes.', 'Ok.']) {
  rmsgs.push({ role: 'user', content: t }); rh = await call('/api/me/rehearse', { method: 'POST', token: tok, body: { messages: rmsgs } }); rmsgs.push({ role: 'assistant', content: rh.d.reply }); if (rh.d.done) break;
}
ok(rh.d.done && rh.d.assessment, 'rehearsal ends with an assessment');
ok((await call('/api/admin/events', { token: ADM })).d[0].id === evBefore && (await call('/api/admin/claims', { token: ADM })).d.every(c => c.owner_email !== email), 'rehearsal stores nothing and alerts nobody');

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
const t0 = Date.now(); const esc = async at => (await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at, emails: [email] } })).d.filter(x => x[0] === email).map(x => x[1]);
ok((await esc(t0 + 10 * DAY)).length === 0, 'nothing before due');
ok((await esc(t0 + 91 * DAY))[0] === 'first reminder', 'first reminder at 91d');
const steps = [];
for (let w = 1; w <= 6; w++) steps.push(...await esc(t0 + 91 * DAY + w * 7 * DAY + 1000));
console.log('   timeline:', steps.join(' | '));
ok(steps.at(-1).startsWith('nominees contacted'), 'nominees contacted after 6 weeks');
ok((await call('/api/me', { token: tok })).d.state === 'nominees_contacted', 'state nominees_contacted');

// nominee claim: account + verified email first, then they say whose vault it is
ok((await call('/api/claimant/start', { method: 'POST', body: { name: 'X', email: 'not-an-email' } })).s === 400, 'claimant needs a valid email');
ok((await call('/api/claim/find', { method: 'POST', body: { ownerEmail: email } })).s === 401, 'find refused before email verified');
const lock = await call('/api/claimant/start', { method: 'POST', body: { name: 'Guesser', email: 'guess@example.com' } });
for (let i = 0; i < 5; i++) await call('/api/claimant/verify', { method: 'POST', body: { claimantId: lock.d.claimantId, code: '000000' } });
ok((await call('/api/claimant/verify', { method: 'POST', body: { claimantId: lock.d.claimantId, code: await otpFor('guess@example.com') } })).s === 429, 'code locked after 5 wrong tries');
const imp = await claimant('Imposter', 'imposter@example.com');
ok((await call('/api/claim/find', { method: 'POST', token: imp, body: { ownerEmail: email } })).s === 404, 'non-nominee gets a generic no-match');
const nt = await claimant('Nom Inee', 'nominee@example.com');
r = await call('/api/claim/find', { method: 'POST', token: nt, body: { ownerEmail: email.toUpperCase() } });
ok(r.s === 200 && r.d.status === 'interview' && r.d.message, 'listed nominee starts a claim'); const ct = r.d.token; const firstMsg = r;
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind.startsWith('email') && e.detail.includes('URGENT') && e.detail.includes(email)), 'owner alerted immediately');
ok((await call('/api/me', { token: tok })).d.openClaim === true, 'owner dashboard shows open claim');
let st;
// Against the live site the interviewer is a real AI, so a role-played claimant (also AI) answers it from a fixed backstory
const STORY = 'You are Nom Inee, wife of Test Owner for 18 years, living in Jumeirah, Dubai. Test Owner (born 3 March 1974, aged 52) died of a heart attack at home on the morning of Tuesday 6 October 2026; the ambulance took him to Mediclinic City Hospital where he was pronounced dead. His brother David Owner and your solicitor Sarah Jones know. The funeral is on 16 October 2026. He told you about Save My Secrets and mentioned it in his letter of wishes. You have the official death certificate from the Dubai Health Authority and can upload it now. Answer the interviewer directly, briefly and truthfully from this story. Invent small consistent details only if asked something not covered.';
async function roleplay(history, story = STORY) {
  const key = fs.existsSync('/root/.smsec/anthropic') ? fs.readFileSync('/root/.smsec/anthropic', 'utf8').trim() : process.env.ANTHROPIC_API_KEY;
  const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: 200, system: story, messages: history.map(h => ({ role: h.ai ? 'user' : 'assistant', content: h.text })) }) });
  return (await r.json()).content[0].text;
}
const live = B.startsWith('https');
async function interview(tok, story) {
  const h = [{ ai: true, text: 'I\'m sorry you\'re dealing with this. To start, can you tell me what has happened?' }]; let res;
  for (let i = 0; i < 12; i++) {
    const msg = live ? await roleplay(h, story) : 'answer ' + i; h.push({ ai: false, text: msg });
    res = (await call('/api/claim/message', { method: 'POST', token: tok, body: { text: msg } })).d; if (res.done || !live && i >= 2) break; h.push({ ai: true, text: res.reply });
  }
  return res;
}
const sibling = (who, owner) => `You are ${who}, sibling of ${owner} (born 1970). ${owner} died of a stroke on 2 October 2026 at Chelsea and Westminster Hospital, London, aged 56. Their partner Jo and their solicitor Mark Lee know; the funeral is on 20 October 2026. ${owner} told you years ago to come to Save My Secrets if anything happened. Answer the interviewer directly, briefly and truthfully from this story, inventing small consistent details only if asked.`;
const scripted = ['I am his wife. He died of a heart attack.', 'Last Tuesday in Dubai, at Mediclinic.', 'His brother and our solicitor know.', 'Yes I have the certificate now.'];
const hist = [{ ai: true, text: firstMsg.d.message }];
for (let i = 0; i < 12; i++) {
  const msg = live ? await roleplay(hist) : scripted[i]; if (!msg) break; hist.push({ ai: false, text: msg });
  r = await call('/api/claim/message', { method: 'POST', token: ct, body: { text: msg } }); st = r.d; if (st.done) break; hist.push({ ai: true, text: st.reply });
}
ok(st.done && st.status === 'awaiting_document', 'interview complete, awaiting certificate'); if (!st.done) console.log('   last AI reply:', st.reply);
ok((await call('/api/claim/status', { token: ct })).d.package === undefined, 'no package before release');
const fd = new FormData(); const bad = new FormData(); bad.append('file', new Blob([Buffer.from('%PDF-1.4 corrupt')], { type: 'application/pdf' }), 'bad.pdf');
if (B.startsWith('https')) ok((await fetch(B + '/api/claim/document', { method: 'POST', headers: { authorization: 'Bearer ' + ct }, body: bad })).status === 400, 'unreadable upload sent back, not a server error');
fd.append('file', new Blob([fs.readFileSync(new URL('./fixture-upload.png', import.meta.url))], { type: 'image/png' }), 'test.png');
r = await fetch(B + '/api/claim/document', { method: 'POST', headers: { authorization: 'Bearer ' + ct }, body: fd }); ok(r.status === 200, 'certificate uploaded');
ok((await call('/api/admin/claims', { token: 'nope' })).s === 401, 'admin requires token');
const cl = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.owner_email === email); const claimId = cl.id; ok(cl.status === 'review' && cl.doc_key, 'claim in review with doc');
ok((await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId, decision: 'approve', note: 'test' } })).s === 200, 'approved');
ok((await call('/api/me', { token: tok })).d.state === 'veto_window', 'veto window started');
const vEnds = (await call('/api/claim/status', { token: ct })).d.vetoEndsAt; ok(vEnds >= Date.now() + 7 * DAY - 60000, 'final check lasts at least veto_days');
ok((await esc(Date.now() + 1000))[0] === 'veto alarm', 'veto alarm sent');
ok(!(await esc(vEnds - DAY)).includes('released'), 'not released before final check ends');
ok((await esc(vEnds + 1000)).includes('released'), 'released after final check');
const pkg = (await call('/api/claim/status', { token: ct })).d.package;
ok(pkg && pkg.serverShare, 'package delivered to nominee');
ok(pkg.releaseMode === 'standard' && !('legacyCode' in pkg), 'standard release package, no printed code needed');
const Kn = await SMS.unlockRelease(pkg.serverShare, pkg.wrappedRelease);
const opened = await SMS.decVault(Kn, pkg.vault);
ok(opened.items[0].title === 'Cold wallet' && opened.letter === 'Dear family, love you.', 'nominee opens the vault, existing letter included');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.detail.includes('nominee@example.com') && e.detail.includes('ready for you')), 'nominee emailed when the vault is released');
const nt2 = await claimant('Nom Inee', 'nominee@example.com');
r = await call('/api/claim/find', { method: 'POST', token: nt2, body: { ownerEmail: email } });
ok(r.s === 200 && r.d.status === 'released' && (await call('/api/claim/status', { token: r.d.token })).d.package, 'nominee can come back on a new device after release');

// Scenario 1b: an existing standard vault keeps working until every nominee has questions, then our copy is deleted
const emailL = `legacy+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: emailL, name: 'Lena Legacy', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); const tokL = r.d.token;
const vL = await SMS.createVault(k.ownerKey, { items: [{ title: 'Will', body: 'In the safe' }] }); await call('/api/me/vault', { method: 'POST', token: tokL, body: vL.upload });
await makeLegacy(emailL, tokL, vL.K, [{ id: 'legacyL1', name: 'Lou One', email: 'lou1@example.com' }, { id: 'legacyL2', name: 'Lou Two', email: 'lou2@example.com' }]);
ok((await call('/api/me', { token: tokL })).d.hasRelease === true, 'existing standard vault starts with our copy');
ok((await call('/api/me/vault', { method: 'POST', token: tokL, body: { vault: vL.upload.vault, wrappedOwner: vL.upload.wrappedOwner, wrappedRelease: 'x' } })).s === 400, 'existing vault: a replacement release copy is refused too');
ok((await addNom(tokL, vL.K, { name: 'Lou Three', email: 'lou3@example.com' })).s === 200 && (await call('/api/me', { token: tokL })).d.hasRelease === true, 'existing vault: adding a set-up nominee keeps the copy while others are not set up');
const shareL = (await call('/api/me/share', { token: tokL })).d.serverShare;
r = await call('/api/me/nominees/legacyL1/questions', { method: 'POST', token: tokL, body: await SMS.buildNomineeKeys(vL.K, shareL, QS) });
ok(r.s === 200 && r.d.removedServerCopy === false && r.d.allSet === false && (await call('/api/me', { token: tokL })).d.hasRelease === true, 'copy kept while one nominee still has no questions');
await (call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: Date.now() + 91 * DAY, emails: [emailL] } }));
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.detail.includes(emailL) && e.detail.includes('Lou Two has no questions yet') && e.detail.includes('Set questions for every nominee so we can delete our copy of your key.')), 'check-in email asks the owner to finish so we can delete our copy');
{ const ci = await mailTo(emailL, 'Quick check-in'); ok(!!ci && !ci.detail.includes('Tip: add') && !ci.detail.includes('to your contacts'), 'check-in email has no contacts tip'); }
await call('/api/me/checkin', { method: 'POST', token: tokL, body: {} });
r = await call('/api/me/nominees/legacyL2/questions', { method: 'POST', token: tokL, body: await SMS.buildNomineeKeys(vL.K, shareL, QS) });
ok(r.s === 200 && r.d.removedServerCopy === true && r.d.allSet === true, 'our copy deleted once every nominee has questions');
{ const mL = (await call('/api/me', { token: tokL })).d; ok(mL.hasRelease === false && mL.releaseMode === 'questions' && mL.nominees.every(n => n.hasQuestions), 'existing vault now opens only with answers'); }
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind === 'server_copy_deleted'), 'deletion logged');

// Scenario 2: owner vetoes by email link during veto window
const email2 = `veto+${Date.now()}@example.com`; const k2Veto = await SMS.deriveFromPassword(pw, kdfSalt);
r = await call('/api/register', { method: 'POST', body: { email: email2, name: 'Alive Owner', authKey: k2Veto.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); const tok2 = r.d.token;
const v2 = await SMS.createVault(k2Veto.ownerKey, { items: [] }); await call('/api/me/vault', { method: 'POST', token: tok2, body: v2.upload });
await call('/api/me/policy', { method: 'POST', token: tok2, body: { proof_required: 'none', checkin_days: 30, grace_weeks: 2, veto_days: 7 } });
ok((await addNom(tok2, v2.K, { name: 'Bro', email: 'bro@example.com', notify_early: true })).s === 200, 'nominee added with their questions in one step');
ok(await hasTip('bro@example.com', 'has named you as a nominee'), 'named-as-nominee email carries the contacts tip');
const me2 = (await call('/api/me', { token: tok2 })).d; const uid2 = me2.nominees[0].user_id;
const bt = await claimant('Bro', 'bro@example.com');
r = await call('/api/claim/find', { method: 'POST', token: bt, body: { u: uid2 } }); const ct2 = r.d.token;
ok((await call('/api/me', { token: tok2 })).d.state === 'overdue', 'claim brings an active owner\'s check-in forward');
st = await interview(ct2, sibling('Bro', 'Alive Owner'));
ok(st.status === 'review', 'proof=none goes straight to review');
const cid2 = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.owner_email === email2).id;
await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId: cid2, decision: 'approve' } });
const alarm = (await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: Date.now() + 1000, emails: [email2] } })).d;
const evs = (await call('/api/admin/events', { token: ADM })).d.filter(e => e.user_id === uid2 && e.detail.includes('/api/checkin?'));
const link = JSON.parse(evs[0].detail).html.match(/href="([^"]+)"/)[1].replace(/&amp;/g, '&');
r = await call(link.replace(/^https?:\/\/[^/]+/, '')); ok(r.s === 302, 'email check-in link works');
ok((await call('/api/me', { token: tok2 })).d.state === 'active', 'owner back to active');
ok((await call('/api/claim/status', { token: ct2 })).d.status === 'vetoed', 'claim vetoed by owner check-in');
r = await call(link.replace(/^https?:\/\/[^/]+/, '').replace(/s=[0-9a-f]+/, 's=deadbeef')); ok(r.s === 400, 'tampered check-in link rejected');
ok((await call(link.replace(/^https?:\/\/[^/]+/, ''))).s === 400, 'check-in link is single use');
const older = (await call('/api/admin/events', { token: ADM })).d.filter(e => e.user_id === uid2 && e.detail.includes('URGENT'))[0];
ok((await call(JSON.parse(older.detail).html.match(/href="([^"]+)"/)[1].replace(/&amp;/g, '&').replace(/^https?:\/\/[^/]+/, ''))).s === 400, 'older check-in links also stop working');

// Scenario 3: a rejected claim puts an active owner back where they were; recovery codes; logout
const email3 = `rej+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: email3, name: 'Third Owner', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
const sec3 = r.d.totpSecret; r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(sec3) } }); let tok3 = r.d.token; const rec3 = r.d.recoveryCodes;
const v3 = await SMS.createVault(k.ownerKey, { items: [] }); await call('/api/me/vault', { method: 'POST', token: tok3, body: v3.upload });
await call('/api/me/policy', { method: 'POST', token: tok3, body: { proof_required: 'none', checkin_days: 90, grace_weeks: 6, veto_days: 7 } });
await addNom(tok3, v3.K, { name: 'Sis', email: 'sis@example.com' });
const next3 = (await call('/api/me', { token: tok3 })).d.nextCheckin;
const st3 = await claimant('Sis', 'sis@example.com');
const ct3 = (await call('/api/claim/find', { method: 'POST', token: st3, body: { ownerEmail: email3 } })).d.token;
await interview(ct3, sibling('Sis', 'Third Owner'));
const cid3 = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.owner_email === email3).id;
await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId: cid3, decision: 'reject' } });
const me3 = (await call('/api/me', { token: tok3 })).d;
ok(me3.state === 'active' && me3.nextCheckin === next3 && !me3.openClaim, 'rejected claim restores owner state and schedule');
ok((await call('/api/claim/status', { token: ct3 })).d.status === 'rejected', 'claimant sees rejection');
ok((await call('/api/logout', { method: 'POST', token: tok3 })).s === 200 && (await call('/api/me', { token: tok3 })).s === 401, 'logout ends the session');
ok((await call('/api/login', { method: 'POST', body: { email: email3, authKey: k.authKey, recovery: 'WRONG-CODE1' } })).s === 401, 'bad recovery code rejected');
r = await call('/api/login', { method: 'POST', body: { email: email3, authKey: k.authKey, recovery: rec3[0].toLowerCase() } });
ok(r.s === 200 && r.d.needsEnrol && r.d.totpSecret !== sec3, 'recovery code logs in and forces new 2FA');
ok(r.d.otpauth.includes('secret=' + r.d.totpSecret) && r.d.otpauth.endsWith(LOGO_PARAM), 're-enrol otpauth URI includes the logo image param');
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); ok(r.s === 200 && r.d.recoveryCodes.length === 10, 're-enrolled with fresh recovery codes');
ok((await call('/api/login', { method: 'POST', body: { email: email3, authKey: k.authKey, recovery: rec3[1] } })).s === 401, 'old recovery codes replaced');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind.startsWith('email') && e.detail.includes('recovery code was used')), 'owner emailed when a recovery code is used');

ok((await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: Date.now() + 90 * DAY } })).s === 400, 'a simulated future run must name its test accounts');
// Scenario 4: nominee questions. A new vault never has a copy we could open; answers open it on the nominee's device
const email4 = `q+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: email4, name: 'Quentin Owner', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } }); const sec4 = r.d.totpSecret;
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(sec4) } }); const tok4 = r.d.token;
const v4 = await SMS.createVault(k.ownerKey, { letter: 'For Ana', items: [{ title: 'Deeds', body: 'With the solicitor' }] });
await call('/api/me/vault', { method: 'POST', token: tok4, body: v4.upload });
await call('/api/me/policy', { method: 'POST', token: tok4, body: { proof_required: 'none', checkin_days: 90, grace_weeks: 2, veto_days: 3 } });
const share4 = (await call('/api/me/share', { token: tok4 })).d.serverShare;
const keysA = await SMS.buildNomineeKeys(v4.K, share4, [{ q: 'Where did we marry?', answer: 'Marbella', alts: ['Puerto Banús'] }, { q: 'Old boat?', answer: 'Sea Biscuit' }, { q: 'First landlord?', answer: 'Mrs Okafor', alts: ['Okafor'] }]);
r = await call('/api/me/nominees', { method: 'POST', token: tok4, body: { name: 'Ana Nominee', email: 'qa@example.com', relationship: 'wife', keys: keysA } }); const nA = r.d.id;
ok(r.s === 200 && nA, 'first nominee added with their questions');
ok(!JSON.stringify(keysA).toLowerCase().includes('marbella') && !JSON.stringify(keysA).toLowerCase().includes('okafor'), 'no answers are ever sent to us');
ok((await call('/api/me', { token: tok4 })).d.hasRelease === false, 'new vault: we never hold a copy, even mid-setup');
const nB = (await addNom(tok4, v4.K, { name: 'Ben Nominee', email: 'qb@example.com', relationship: 'son' }, [{ q: 'Q1', answer: 'old one' }, { q: 'Q2', answer: 'old two' }, { q: 'Q3', answer: 'old three' }])).d.id;
const keysB = await SMS.buildNomineeKeys(v4.K, share4, [{ q: 'Q1', answer: 'alpha one' }, { q: 'Q2', answer: 'bravo two' }, { q: 'Q3', answer: 'charlie three' }]);
r = await call(`/api/me/nominees/${nB}/questions`, { method: 'POST', token: tok4, body: keysB }); ok(r.s === 200 && r.d.allSet === true && r.d.removedServerCopy === false, 'questions can be changed; there was never a copy to delete');
const me4 = (await call('/api/me', { token: tok4 })).d; ok(me4.hasRelease === false && me4.nominees.length === 2 && me4.nominees.every(n => n.hasQuestions), 'owner sees every nominee set up and no copy held');
ok((await call('/api/me/nominees/' + nA + '/questions', { method: 'POST', token: tok4, body: { questions: ['a'], salts: [], wraps: {}, verifiers: {} } })).s === 400, 'malformed questions refused');
ok((await call('/api/me/nominees', { method: 'POST', token: tok4, body: { name: 'Cal Nominee', email: 'qc@example.com' } })).s === 400, 'nominee without questions cannot be added');
// A nominee row with no questions (as an older vault might have) can't start a claim on a vault with no copy
d1(`INSERT INTO nominees (id,user_id,name,email,notify_early,created_at) VALUES ('noqnom4',(SELECT id FROM users WHERE email='${email4}'),'Zed Nominee','qz@example.com',0,${Date.now()})`);
ok((await call('/api/me', { token: tok4 })).d.nominees.some(n => n.name === 'Zed Nominee' && !n.hasQuestions), 'owner sees the nominee is not set up');
ok((await call('/api/claim/find', { method: 'POST', token: await claimant('Zed Nominee', 'qz@example.com'), body: { ownerEmail: email4 } })).s === 404, 'nominee without questions cannot claim or get a release package');
await call('/api/me/nominees/noqnom4', { method: 'DELETE', token: tok4 });
const ta = await claimant('Ana Nominee', 'qa@example.com');
const cta = (await call('/api/claim/find', { method: 'POST', token: ta, body: { ownerEmail: email4 } })).d.token;
await interview(cta, sibling('Ana', 'Quentin Owner'));
const cidA = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.owner_email === email4).id;
await call('/api/admin/decide', { method: 'POST', token: ADM, body: { claimId: cidA, decision: 'approve' } });
const end4 = (await call('/api/claim/status', { token: cta })).d.vetoEndsAt;
ok((await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: end4 + 1000, emails: [email4] } })).d.some(x => x[0] === email4 && x[1] === 'released'), 'questions vault released after final check');
const pk = (await call('/api/claim/status', { token: cta })).d.package;
ok(pk.releaseMode === 'questions' && pk.questions.length === 3 && !pk.serverShare && !pk.vault, 'release shows questions only, nothing that opens the vault');
let pr = await SMS.answerProofs(pk.salts, ['Paris', 'Titanic', 'Smith']);
r = await call('/api/claim/unlock', { method: 'POST', token: cta, body: { proofs: pr.proofs } }); ok(r.s === 401 && !r.d.serverShare, 'wrong answers refused');
pr = await SMS.answerProofs(pk.salts, ['puerto banus', 'no idea', 'the OKAFOR']);
r = await call('/api/claim/unlock', { method: 'POST', token: cta, body: { proofs: pr.proofs } });
ok(r.s === 200 && r.d.pair === '02', 'two of three answers accepted (alternative spelling, accents, capitals)');
const KA = await SMS.unlockWithAnswers(r.d.serverShare, r.d.wrapped, pr.keys[r.d.pair]);
ok((await SMS.decVault(KA, r.d.vault)).letter === 'For Ana', 'nominee opens the vault with their answers');
const burst = await Promise.all(Array.from({ length: 10 }, () => call('/api/claim/unlock', { method: 'POST', token: cta, body: { proofs: { '01': 'a'.repeat(64) } } })));
ok(burst.filter(x => x.s === 401).length === 3 && burst.filter(x => x.s === 429).length === 7, 'ten wrong tries at once: only three get checked, the rest must wait');
ok(burst.some(x => x.d.retryAt > Date.now() + 3500000), 'third wrong try means an hour wait');
ok((await call('/api/claim/unlock', { method: 'POST', token: cta, body: { proofs: pr.proofs } })).s === 429, 'even right answers wait until the hour is up');
// The owner turns out to be alive and logs in: the release is withdrawn
r = await call('/api/login', { method: 'POST', body: { email: email4, authKey: k.authKey, code: totp(sec4) } });
ok(r.s === 200 && !(await call('/api/claim/status', { token: cta })).d.package, 'owner logs in after release: nothing more is handed out');
ok((await call('/api/claim/unlock', { method: 'POST', token: cta, body: { proofs: pr.proofs } })).s === 403, 'owner alive: answers no longer unlock anything');

// Rate limit: a 4th code request for the same email within the hour is refused
for (let i = 0; i < 3; i++) await call('/api/claimant/start', { method: 'POST', body: { name: 'Spam', email: 'spam@example.com' } });
ok((await call('/api/claimant/start', { method: 'POST', body: { name: 'Spam', email: 'spam@example.com' } })).s === 429, 'code requests rate limited per email');

// Invite codes tied to email: wrong email rejected, re-approval deactivates old code
const tieEmail1 = 'tie1+' + Date.now() + '@x.com', tieEmail2 = 'tie2+' + Date.now() + '@x.com';
await call('/api/waitlist', { method: 'POST', body: { email: tieEmail1, source: 'test-tie' } });
const tieRes1 = await call('/api/admin/waitlist/invite', { method: 'POST', token: ADM, body: { email: tieEmail1 } });
ok(tieRes1.s === 200 && tieRes1.d.sent === 1, 'personal invite sent');
const tieEv1 = (await call('/api/admin/events', { token: ADM })).d.find(e => e.kind.startsWith('email') && e.detail.includes(tieEmail1) && e.detail.includes('approved'));
const tieCode1 = tieEv1 ? JSON.parse(tieEv1.detail).html.match(/code=([A-Z0-9]{6})/)[1] : null;
ok(tieCode1, 'personal code extracted');
{ const h = JSON.parse(tieEv1.detail).html; ok(h.includes('Create your vault') && !h.replace(/href="[^"]*"/g, '').includes(tieCode1) && !/invite code/i.test(h), 'approval email says "Create your vault" and shows no code to type'); }
const GENERIC_INV = "That invite code isn't valid or has been used up.", USED_INV = 'This invite has already been used to create an account. Log in to carry on.';
let ic = await call('/api/invite/check', { method: 'POST', body: { code: tieCode1, email: tieEmail2 } });
ok(ic.s === 400 && !ic.d.used && ic.d.error === GENERIC_INV && !JSON.stringify(ic.d).includes('tie1'), 'link with the wrong email fails at check time with the generic message, tied email not revealed');
ok((await call('/api/invite/check', { method: 'POST', body: { code: tieCode1, email: tieEmail1.toUpperCase() } })).s === 200 && (await call('/api/invite/check', { method: 'POST', body: { code: tieCode1 } })).s === 200, 'unused personal code passes with its own email or no email');
const kdfSaltTie = SMS.b64(SMS.rand(16));
const kTieWrong = await SMS.deriveFromPassword('password tie wrong', kdfSaltTie);
ok((await call('/api/register', { method: 'POST', body: { email: tieEmail2, name: 'Wrong Email', authKey: kTieWrong.authKey, kdfSalt: kdfSaltTie, inviteCode: tieCode1 } })).s === 403, 'invite code refused for mismatched email');
const kTieRight = await SMS.deriveFromPassword('password tie right', kdfSaltTie);
ok((await call('/api/register', { method: 'POST', body: { email: tieEmail1, name: 'Right Email', authKey: kTieRight.authKey, kdfSalt: kdfSaltTie, inviteCode: tieCode1 } })).s === 200, 'invite code accepted for matching email');
// Used invite (account created, then abandoned at the 2FA screen): reopening the link points to Log in
ic = await call('/api/invite/check', { method: 'POST', body: { code: tieCode1, email: tieEmail1 } });
ok(ic.s === 400 && ic.d.used === true && ic.d.ok === false && ic.d.error === USED_INV, 'used invite link gets the distinct "log in to carry on" response');
ic = await call('/api/invite/check', { method: 'POST', body: { code: tieCode1.toLowerCase() } });
ok(ic.d.used === true && ic.d.error === USED_INV && Object.keys(ic.d).sort().join() === 'error,ok,used', 'used invite without email: same response, nothing else returned');
ic = await call('/api/invite/check', { method: 'POST', body: { code: tieCode1, email: tieEmail2 } });
ok(ic.s === 400 && !ic.d.used && ic.d.error === GENERIC_INV, 'used invite with a different email stays generic');
ic = await call('/api/invite/check', { method: 'POST', body: { code: 'NOSUCHCODE' + Date.now() } });
ok(ic.s === 400 && !ic.d.used && ic.d.error === GENERIC_INV, 'unknown code stays generic');
const kTieAgain = await SMS.deriveFromPassword('password tie again', kdfSaltTie);
let rr = await call('/api/register', { method: 'POST', body: { email: 'tie3+' + Date.now() + '@x.com', name: 'Again', authKey: kTieAgain.authKey, kdfSalt: kdfSaltTie, inviteCode: one } });
ok(rr.s === 403 && rr.d.used === true && rr.d.error === USED_INV, 'register with a used (untied) code returns the used response');
rr = await call('/api/register', { method: 'POST', body: { email: tieEmail2, name: 'Wrong Again', authKey: kTieAgain.authKey, kdfSalt: kdfSaltTie, inviteCode: tieCode1 } });
ok(rr.s === 403 && !rr.d.used && rr.d.error === GENERIC_INV, 'register with a used code tied to someone else stays generic');
rr = await call('/api/login', { method: 'POST', body: { email: tieEmail1, authKey: kTieRight.authKey } });
ok(rr.s === 200 && rr.d.needsEnrol === true && rr.d.canSkip === true && !!rr.d.totpSecret, 'account abandoned at 2FA logs in and resumes enrolment, with skip available');
// Re-approve the same person: old unused codes deactivated
const reApproveEmail = 'reapprove+' + Date.now() + '@x.com';
await call('/api/waitlist', { method: 'POST', body: { email: reApproveEmail, source: 'test-reapprove' } });
await call('/api/admin/waitlist/invite', { method: 'POST', token: ADM, body: { email: reApproveEmail } });
const evs1 = (await call('/api/admin/events', { token: ADM })).d;
const code1st = evs1.find(e => e.kind.startsWith('email') && e.detail.includes(reApproveEmail) && e.detail.includes('approved')) ? JSON.parse(evs1.find(e => e.kind.startsWith('email') && e.detail.includes(reApproveEmail)).detail).html.match(/code=([A-Z0-9]{6})/)[1] : null;
await call('/api/admin/waitlist/invite', { method: 'POST', token: ADM, body: { email: reApproveEmail } });
const evs2 = (await call('/api/admin/events', { token: ADM })).d;
const code2nd = evs2.filter(e => e.kind.startsWith('email') && e.detail.includes(reApproveEmail) && e.detail.includes('approved')).map(e => JSON.parse(e.detail).html.match(/code=([A-Z0-9]{6})/)?.[1]).filter(c => c !== code1st)[0];
ok(code2nd && code1st !== code2nd, 're-approval issues a new code');
ic = await call('/api/invite/check', { method: 'POST', body: { code: code1st } });
ok(ic.s === 400 && !ic.d.used && ic.d.error === GENERIC_INV, 'first code deactivated after re-approval (generic, not "used")');
ok((await call('/api/invite/check', { method: 'POST', body: { code: code2nd } })).s === 200, 'second code still valid');
const wlCheck = await call('/api/admin/waitlist', { token: ADM });
const reApproveRow = wlCheck.d.find(r => r.email === reApproveEmail);
ok(reApproveRow && reApproveRow.invited_at && reApproveRow.invite_code === code2nd, 'waitlist row marked as invited with latest code');

// Unapproved claim does NOT release even after veto window and cron
const emailUnapp = `unapp+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: emailUnapp, name: 'Unapproved Owner', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); const tokUnapp = r.d.token;
const vU = await SMS.createVault(k.ownerKey, { items: [] }); await call('/api/me/vault', { method: 'POST', token: tokUnapp, body: vU.upload });
await call('/api/me/policy', { method: 'POST', token: tokUnapp, body: { proof_required: 'none', checkin_days: 30, grace_weeks: 2, veto_days: 3 } });
await addNom(tokUnapp, vU.K, { name: 'Claimant Unapp', email: 'claimunapp@example.com' });
const meUnapp = (await call('/api/me', { token: tokUnapp })).d; const uidUnapp = meUnapp.nominees[0].user_id;
const ctUnapp = (await call('/api/claim/find', { method: 'POST', token: await claimant('Claimant Unapp', 'claimunapp@example.com'), body: { u: uidUnapp } })).d.token;
await interview(ctUnapp, sibling('Claimant Unapp', 'Unapproved Owner'));
const clUnapp = (await call('/api/admin/claims', { token: ADM })).d.find(c => c.owner_email === emailUnapp);
ok(clUnapp.status === 'review', 'unapproved claim in review');
// Don't call /api/admin/decide - skip approval
const vetoEndsUnapp = Date.now() + 3 * DAY + 1000;
await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: vetoEndsUnapp, emails: [emailUnapp] } });
const stUnapp = (await call('/api/claim/status', { token: ctUnapp })).d;
ok(stUnapp.status === 'review' && !stUnapp.package && !stUnapp.vetoEndsAt, 'unapproved claim does not enter veto window or release');
ok((await call('/api/me', { token: tokUnapp })).d.state === 'overdue', 'owner state unaffected by unapproved claim');
// Even a year later, with the escalation job run again, an unapproved claim stays in review and nothing is released
await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: Date.now() + 400 * DAY, emails: [emailUnapp] } });
const stLater = (await call('/api/claim/status', { token: ctUnapp })).d;
ok(stLater.status === 'review' && !stLater.package && (await call('/api/me', { token: tokUnapp })).d.state !== 'released', 'unapproved claim still not released a year later');
// What the claimant actually sees: run the real checkStatus() from /claim against stubbed status responses
const claimHtml = (await call('/claim')).d;
ok(typeof claimHtml === 'string' && claimHtml.includes("we'll be in touch by email"), '/claim contains the pending message');
const csSrc = claimHtml.match(/async function checkStatus\(\) \{[\s\S]*?\n\}\n/)?.[0];
async function claimScreen(status) {
  const els = {}; const el = id => els[id] ||= { textContent: '', innerHTML: '', classList: { toggle() {}, add() {}, remove() {} } }; let shown = null;
  const run = vm.runInNewContext(`(async () => { ${csSrc}; await checkStatus(); })`, { $: el, step: n => { shown = n; }, call: async () => ({ status, ownerFirstName: 'Sam', vetoEndsAt: Date.now() + DAY }), owner: '', pkg: null, esc: x => x, waitNote() {}, Date });
  await run(); return { shown, text: els.s5msg?.textContent || '' };
}
const scrReview = csSrc ? await claimScreen('review') : {};
ok(scrReview.shown === 's5' && scrReview.text === "We've completed our checks on your request and we'll be in touch by email.", "claimant in 'review' sees the completed-checks message");
ok(!/person|team|human|manual|review/i.test(scrReview.text || 'x person'), 'pending message does not mention human review');
const scrOdd = csSrc ? await claimScreen('something_new') : {};
ok(scrOdd.shown === 's5' && scrOdd.text === "We'll be in touch by email when we have an update.", 'unknown status gets the neutral fallback');

// Scenario 5: 2FA is optional but strongly recommended
const email5 = `skip+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: email5, name: 'Skip Owner', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
ok(r.s === 200 && r.d.canSkip === true, 'signup offers skipping 2FA'); const enrol5 = r.d.token, signupSecret5 = r.d.totpSecret;
ok((await call('/api/me', { token: enrol5 })).s === 401, 'enrol session cannot reach the vault before skipping');
ok((await call('/api/me/2fa/setup', { method: 'POST', token: enrol5 })).s === 401, 'enrol session cannot use the dashboard 2FA setup');
ok((await call('/api/2fa/skip', { method: 'POST' })).s === 401, 'skip needs a session');
r = await call('/api/2fa/skip', { method: 'POST', token: enrol5 });
ok(r.s === 200 && !!r.d.token && r.d.kdfSalt === kdfSalt && !r.d.recoveryCodes, 'skip anyway upgrades to a full session, with no recovery codes'); const tok5 = r.d.token;
ok((await call('/api/2fa/skip', { method: 'POST', token: enrol5 })).s === 401, 'the same enrol session cannot skip twice');
ok((await call('/api/2fa/skip', { method: 'POST', token: tok5 })).s === 401, 'a full session cannot call skip');
ok((await call('/api/2fa/enable', { method: 'POST', token: enrol5, body: { code: totp(signupSecret5) } })).s === 401, 'spent enrol session cannot enable 2FA either');
let me5 = (await call('/api/me', { token: tok5 })).d;
ok(me5.totpEnabled === false && me5.email === email5, 'dashboard reports 2FA is off');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind === '2fa_skipped'), '2fa_skipped event logged');
// Admin uses its own admin token; an owner session (with or without 2FA) never opens it
ok((await call('/api/admin/claims', { token: tok5 })).s === 401 && (await call('/api/admin/events', { token: tok5 })).s === 401, 'password-only owner session cannot reach admin');
ok((await call('/api/admin/claims')).s === 401 && (await call('/api/admin/claims', { token: ADM })).s === 200, 'admin still needs the admin token');
// Login after skipping: password alone gives a full session
ok((await call('/api/login', { method: 'POST', body: { email: email5, authKey: 'wrong' } })).s === 401, 'skipped account: wrong password still rejected');
r = await call('/api/login', { method: 'POST', body: { email: email5, authKey: k.authKey } });
ok(r.s === 200 && !r.d.needsEnrol && (await call('/api/me', { token: r.d.token })).s === 200, 'skipped account logs in with password only'); const otherTok5 = r.d.token;
// Abandoned enrolment (never skipped): login still shows the enrol screen, now with the skip option
const email6 = `abandon+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: email6, name: 'Abandon Owner', authKey: k.authKey, kdfSalt, inviteCode: 'TESTCONF' } }); const sec6 = r.d.totpSecret;
r = await call('/api/login', { method: 'POST', body: { email: email6, authKey: k.authKey } });
ok(r.s === 200 && r.d.needsEnrol && r.d.canSkip === true && r.d.totpSecret === sec6 && r.d.otpauth.endsWith(LOGO_PARAM), 'abandoned enrolment: login shows enrol with skip offered');
ok((await call('/api/me', { token: r.d.token })).s === 401, 'abandoned enrolment: no vault access without enrolling or skipping');
// Turn 2FA on later from the dashboard: always a fresh secret, then the code is required at login
r = await call('/api/me/2fa/setup', { method: 'POST', token: tok5 }); const secA = r.d.totpSecret;
ok(r.s === 200 && secA && secA !== signupSecret5 && r.d.otpauth.includes('secret=' + secA) && r.d.otpauth.endsWith(LOGO_PARAM), 'setup later gives a fresh secret and the logo URI');
r = await call('/api/me/2fa/setup', { method: 'POST', token: tok5 }); const secB = r.d.totpSecret;
ok(r.s === 200 && secB !== secA, 'each setup generates a new secret');
ok((await call('/api/me/2fa/enable', { method: 'POST', token: tok5, body: { code: totp(signupSecret5) } })).s === 400, 'old signup secret is never accepted');
ok((await call('/api/me/2fa/enable', { method: 'POST', token: tok5, body: { code: totp(secA) } })).s === 400, 'superseded setup secret is not accepted');
r = await call('/api/me/2fa/enable', { method: 'POST', token: tok5, body: { code: totp(secB) } });
ok(r.s === 200 && Array.isArray(r.d.recoveryCodes) && r.d.recoveryCodes.length === 10, '2FA turned on later, with 10 recovery codes'); const rec5 = r.d.recoveryCodes;
me5 = (await call('/api/me', { token: tok5 })).d; ok(me5.totpEnabled === true && me5.recoveryLeft === 10, 'dashboard reports 2FA is on');
ok((await call('/api/me', { token: otherTok5 })).s === 401, 'other password-only sessions are signed out when 2FA is turned on');
ok((await call('/api/me/2fa/setup', { method: 'POST', token: tok5 })).s === 409, 'cannot restart setup once 2FA is on');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind === '2fa_enabled_later'), '2fa_enabled_later event logged');
ok((await call('/api/login', { method: 'POST', body: { email: email5, authKey: k.authKey } })).s === 401, 'after turning 2FA on, password alone no longer logs in');
r = await call('/api/login', { method: 'POST', body: { email: email5, authKey: k.authKey, code: totp(secB) } });
ok(r.s === 200 && !r.d.needsEnrol, 'after turning 2FA on, password plus code logs in');
ok((await call('/api/admin/claims', { token: r.d.token })).s === 401, 'owner session with 2FA cannot reach admin either');
// A recovery-code re-enrolment can never be skipped, so 2FA can't be switched off that way
r = await call('/api/login', { method: 'POST', body: { email: email5, authKey: k.authKey, recovery: rec5[0] } });
ok(r.s === 200 && r.d.needsEnrol && r.d.canSkip === false, 'recovery re-enrolment does not offer skip');
ok((await call('/api/2fa/skip', { method: 'POST', token: r.d.token })).s === 403, 'recovery re-enrolment cannot skip');
r = await call('/api/login', { method: 'POST', body: { email: email5, authKey: k.authKey } });
ok(r.s === 200 && r.d.needsEnrol && r.d.canSkip === false && (await call('/api/me', { token: r.d.token })).s === 401, 'after a recovery code, password alone still only reaches enrol');

// Admin "User N": sign-up order worked out on the server, admin endpoints only, raw id still returned for look-ups
{ const evs = (await call('/api/admin/events', { token: ADM })).d; const noOf = id => evs.find(e => e.user_id === id)?.user_no;
  const seen = new Map(); let consistent = true; for (const e of evs.filter(e => e.user_id)) { if (seen.has(e.user_id) && seen.get(e.user_id) !== e.user_no) consistent = false; seen.set(e.user_id, e.user_no); }
  ok(consistent && [...seen.values()].every(n => n === null || (Number.isInteger(n) && n >= 1)), 'admin events carry a stable user number per user');
  ok(noOf(uid2) >= 1 && noOf(uidUnapp) > noOf(uid2), 'users are numbered in sign-up order');
  ok(new Set([...seen.entries()].filter(([, n]) => n).map(([, n]) => n)).size === [...seen.values()].filter(Boolean).length, 'no two users share a number');
  d1(`INSERT INTO events (user_id, kind, detail, at) VALUES ('gone-user-0000', 'test_deleted_user', '{}', ${Date.now()})`);
  const gone = (await call('/api/admin/events', { token: ADM })).d.find(e => e.kind === 'test_deleted_user');
  ok(gone && gone.user_id === 'gone-user-0000' && gone.user_no === null, 'an event whose user no longer exists has no number (shown as "Deleted user")');
  ok((await call('/api/admin/claims', { token: ADM })).d.every(c => Number.isInteger(c.user_no)), 'claims carry the owner\'s user number');
  ok((await call('/api/admin/events', { token: 'nope' })).s === 401 && (await call('/api/admin/events')).s === 401, 'events (with user numbers) still need the admin token');
  const mine = await call('/api/me', { token: tok2 }); ok(mine.s === 200 && !JSON.stringify(mine.d).includes('user_no'), 'owners never see user numbers'); }

console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); process.exit(fails ? 1 : 0);

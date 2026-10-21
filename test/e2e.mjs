import fs from 'fs'; import vm from 'vm'; import crypto from 'crypto';
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
const otpFor = async to => { const e = (await call('/api/admin/events', { token: ADM })).d.find(e => e.kind.startsWith('email') && e.detail.includes('verification code') && e.detail.includes(to)); return JSON.parse(e.detail).html.match(/<b>(\d{6})<\/b>/)[1]; };
async function claimant(name, mail) {
  const s1 = await call('/api/claimant/start', { method: 'POST', body: { name, email: mail } });
  const v = await call('/api/claimant/verify', { method: 'POST', body: { claimantId: s1.d.claimantId, code: await otpFor(mail) } });
  return v.d.token;
}
const email = `neil+${Date.now()}@example.com`, pw = 'correct horse battery staple';

const wlEmail = 'w' + Date.now() + '@example.com';
ok((await call('/api/waitlist', { method: 'POST', body: { email: wlEmail, source: 'conf' } })).s === 200, 'waitlist');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind.startsWith('email') && e.detail.includes(wlEmail) && e.detail.includes('access request')), 'waitlist confirmation email sent');
ok((await call('/api/waitlist', { method: 'POST', body: { email: 'nope' } })).s === 400, 'waitlist rejects bad email');
ok((await call('/api/subscribe', { method: 'POST', body: { email: 's' + Date.now() + '@x.com', source: 'holding-page' } })).s === 200, 'old /api/subscribe still works');
ok((await call('/no-such-page')).s === 404, 'unknown URL returns 404');
for (const pg of ['/privacy', '/terms', '/claim', '/preview']) ok((await call(pg)).s === 200, pg + ' serves');
ok((await call('/')).h.get('content-security-policy')?.includes("frame-ancestors 'none'"), 'CSP header set');

ok((await call('/api/admin/invites', { method: 'POST', token: ADM, body: { code: 'test-conf', label: 'test', max_uses: 1000 } })).s === 200, 'invite created');
r0 = await call('/api/admin/waitlist/invite', { method: 'POST', token: ADM, body: { code: 'TESTCONF', emails: [wlEmail] } });
ok(r0.s === 200 && r0.d.sent === 1, 'admin emails an invite to a waitlist signup');
ok((await call('/api/admin/waitlist', { token: ADM })).d.find(w => w.email === wlEmail)?.invite_code === 'TESTCONF', 'waitlist row marked invited');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.detail.includes(wlEmail) && e.detail.includes('/app?invite=TESTCONF')), 'invite email carries the sign-up link');
ok((await call('/api/feedback', { method: 'POST', body: { text: 'The rehearse tab is great', page: '/app' } })).s === 200, 'feedback accepted');
ok((await call('/api/admin/feedback', { token: ADM })).d.some(f => f.text === 'The rehearse tab is great'), 'feedback visible in admin');
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
ok(Array.isArray(r.d.recoveryCodes) && r.d.recoveryCodes.length === 10, '10 recovery codes issued');

const contents = { letter: 'Dear family, love you.', items: [{ type: 'Seed phrase / wallet', title: 'Cold wallet', body: 'abandon ability able about above absent absorb abstract absurd abuse access accident' }] };
const v = await SMS.createVault(k.ownerKey, contents, 'sovereign');
ok(/^[A-Z2-9]{4}(-[A-Z2-9]{4}){7}$/.test(v.legacyCode), 'legacy code format ' + v.legacyCode);
ok((await call('/api/me/vault', { method: 'POST', token: tok, body: v.upload })).s === 200, 'vault sealed');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.detail.includes(email) && e.detail.includes('Your vault is set up')), 'welcome email after sealing');
// server must not be able to decrypt with S alone
let serverAlone = true; try { await SMS.unlockRelease(v.upload.serverShare, v.upload.wrappedRelease, SMS.codeEncode(new Uint8Array(20)), 'sovereign'); } catch { serverAlone = false; }
ok(!serverAlone, 'server share alone cannot open vault');

ok((await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'Nom Inee', email: 'nominee@example.com', phone: '+447700900000', relationship: 'wife' } })).s === 200, 'nominee added');
ok((await call('/api/me/nominees', { method: 'POST', token: tok, body: { name: 'No Plus', email: 'noplus@example.com', phone: '07700 900000' } })).s === 400, 'phone without country code refused');
ok((await call('/api/me/policy', { method: 'POST', token: tok, body: { phone: '00971 50 123 4567' } })).s === 200 && (await call('/api/me', { token: tok })).d.phone === '+971501234567', 'phone tidied to +971501234567');
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
let wrongCodeOpens = true; try { await SMS.unlockRelease(pkg.serverShare, pkg.wrappedRelease, SMS.codeEncode(SMS.rand(20)), pkg.releaseMode); } catch { wrongCodeOpens = false; }
ok(!wrongCodeOpens, 'wrong legacy code fails');
const Kn = await SMS.unlockRelease(pkg.serverShare, pkg.wrappedRelease, v.legacyCode.toLowerCase().replace(/-/g, ' '), pkg.releaseMode);
ok((await SMS.decVault(Kn, pkg.vault)).items[0].title === 'Cold wallet', 'nominee opens vault with legacy code (lower case, spaces)');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.detail.includes('nominee@example.com') && e.detail.includes('ready for you')), 'nominee emailed when the vault is released');
const nt2 = await claimant('Nom Inee', 'nominee@example.com');
r = await call('/api/claim/find', { method: 'POST', token: nt2, body: { ownerEmail: email } });
ok(r.s === 200 && r.d.status === 'released' && (await call('/api/claim/status', { token: r.d.token })).d.package, 'nominee can come back on a new device after release');

// Scenario 2: owner vetoes by email link during veto window
const email2 = `veto+${Date.now()}@example.com`; const k2 = await SMS.deriveFromPassword(pw, kdfSalt);
r = await call('/api/register', { method: 'POST', body: { email: email2, name: 'Alive Owner', authKey: k2.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); const tok2 = r.d.token;
await call('/api/me/vault', { method: 'POST', token: tok2, body: (await SMS.createVault(k2.ownerKey, { items: [] }, 'standard')).upload });
await call('/api/me/policy', { method: 'POST', token: tok2, body: { proof_required: 'none', checkin_days: 30, grace_weeks: 2, veto_days: 7 } });
await call('/api/me/nominees', { method: 'POST', token: tok2, body: { name: 'Bro', email: 'bro@example.com' } });
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
r = await call('/api/register', { method: 'POST', body: { email: email3, name: 'Third Owner', authKey: k2.authKey, kdfSalt, inviteCode: 'TESTCONF' } });
const sec3 = r.d.totpSecret; r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(sec3) } }); let tok3 = r.d.token; const rec3 = r.d.recoveryCodes;
await call('/api/me/vault', { method: 'POST', token: tok3, body: (await SMS.createVault(k2.ownerKey, { items: [] }, 'standard')).upload });
await call('/api/me/policy', { method: 'POST', token: tok3, body: { proof_required: 'none', checkin_days: 90, grace_weeks: 6, veto_days: 7 } });
await call('/api/me/nominees', { method: 'POST', token: tok3, body: { name: 'Sis', email: 'sis@example.com' } });
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
ok((await call('/api/login', { method: 'POST', body: { email: email3, authKey: k2.authKey, recovery: 'WRONG-CODE1' } })).s === 401, 'bad recovery code rejected');
r = await call('/api/login', { method: 'POST', body: { email: email3, authKey: k2.authKey, recovery: rec3[0].toLowerCase() } });
ok(r.s === 200 && r.d.needsEnrol && r.d.totpSecret !== sec3, 'recovery code logs in and forces new 2FA');
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(r.d.totpSecret) } }); ok(r.s === 200 && r.d.recoveryCodes.length === 10, 're-enrolled with fresh recovery codes');
ok((await call('/api/login', { method: 'POST', body: { email: email3, authKey: k2.authKey, recovery: rec3[1] } })).s === 401, 'old recovery codes replaced');
ok((await call('/api/admin/events', { token: ADM })).d.some(e => e.kind.startsWith('email') && e.detail.includes('recovery code was used')), 'owner emailed when a recovery code is used');

ok((await call('/api/admin/run-escalation', { method: 'POST', token: ADM, body: { at: Date.now() + 90 * DAY } })).s === 400, 'a simulated future run must name its test accounts');
// Scenario 4: nominee questions. We delete our openable copy once every nominee has questions; answers open it on the nominee's device
const email4 = `q+${Date.now()}@example.com`;
r = await call('/api/register', { method: 'POST', body: { email: email4, name: 'Quentin Owner', authKey: k2.authKey, kdfSalt, inviteCode: 'TESTCONF' } }); const sec4 = r.d.totpSecret;
r = await call('/api/2fa/enable', { method: 'POST', token: r.d.token, body: { code: totp(sec4) } }); const tok4 = r.d.token;
const v4 = await SMS.createVault(k2.ownerKey, { letter: 'For Ana', items: [{ title: 'Deeds', body: 'With the solicitor' }] }, 'standard');
await call('/api/me/vault', { method: 'POST', token: tok4, body: v4.upload });
await call('/api/me/policy', { method: 'POST', token: tok4, body: { proof_required: 'none', checkin_days: 90, grace_weeks: 2, veto_days: 3 } });
const nA = (await call('/api/me/nominees', { method: 'POST', token: tok4, body: { name: 'Ana Nominee', email: 'qa@example.com', relationship: 'wife' } })).d.id;
const nB = (await call('/api/me/nominees', { method: 'POST', token: tok4, body: { name: 'Ben Nominee', email: 'qb@example.com', relationship: 'son' } })).d.id;
const share4 = (await call('/api/me/share', { token: tok4 })).d.serverShare;
const keysA = await SMS.buildNomineeKeys(v4.K, share4, [{ q: 'Where did we marry?', answer: 'Marbella', alts: ['Puerto Banús'] }, { q: 'Old boat?', answer: 'Sea Biscuit' }, { q: 'First landlord?', answer: 'Mrs Okafor', alts: ['Okafor'] }]);
r = await call(`/api/me/nominees/${nA}/questions`, { method: 'POST', token: tok4, body: keysA }); ok(r.s === 200 && !r.d.removedServerCopy, 'questions saved for first nominee');
ok(!JSON.stringify(keysA).toLowerCase().includes('marbella') && !JSON.stringify(keysA).toLowerCase().includes('okafor'), 'no answers are ever sent to us');
ok((await call('/api/me', { token: tok4 })).d.hasRelease === true, 'our copy kept while a nominee has no questions');
const keysB = await SMS.buildNomineeKeys(v4.K, share4, [{ q: 'Q1', answer: 'alpha one' }, { q: 'Q2', answer: 'bravo two' }, { q: 'Q3', answer: 'charlie three' }]);
r = await call(`/api/me/nominees/${nB}/questions`, { method: 'POST', token: tok4, body: keysB }); ok(r.d.removedServerCopy === true, 'our copy deleted once every nominee has questions');
const me4 = (await call('/api/me', { token: tok4 })).d; ok(me4.hasRelease === false && me4.nominees.every(n => n.hasQuestions), 'owner sees we can no longer open it');
ok((await call('/api/me/nominees/' + nA + '/questions', { method: 'POST', token: tok4, body: { questions: ['a'], salts: [], wraps: {}, verifiers: {} } })).s === 400, 'malformed questions refused');
await call('/api/me/nominees', { method: 'POST', token: tok4, body: { name: 'Cal Nominee', email: 'qc@example.com' } });
ok((await call('/api/claim/find', { method: 'POST', token: await claimant('Cal Nominee', 'qc@example.com'), body: { ownerEmail: email4 } })).s === 404, 'nominee without questions cannot claim once our copy is gone');
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
r = await call('/api/login', { method: 'POST', body: { email: email4, authKey: k2.authKey, code: totp(sec4) } });
ok(r.s === 200 && !(await call('/api/claim/status', { token: cta })).d.package, 'owner logs in after release: nothing more is handed out');
ok((await call('/api/claim/unlock', { method: 'POST', token: cta, body: { proofs: pr.proofs } })).s === 403, 'owner alive: answers no longer unlock anything');

// Rate limit: a 4th code request for the same email within the hour is refused
for (let i = 0; i < 3; i++) await call('/api/claimant/start', { method: 'POST', body: { name: 'Spam', email: 'spam@example.com' } });
ok((await call('/api/claimant/start', { method: 'POST', body: { name: 'Spam', email: 'spam@example.com' } })).s === 429, 'code requests rate limited per email');

console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); process.exit(fails ? 1 : 0);

// Full owner journey in an iPhone-sized browser: sign up, use the vault, log out, log back in, lost-phone recovery
import { chromium, devices } from 'playwright'; import crypto from 'crypto';
const B = process.env.B || 'http://localhost:8787', ADM = process.env.ADM || 'admin-dev-token', OUT = process.env.OUT || 'shots';
function totp(secret, step = 0) { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of secret.replace(/\s/g, '')) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(Date.now() / 30000) + step, 4); const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0'); }
let fails = 0; const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
const inv = 'JOURNEY' + Date.now();
await fetch(B + '/api/admin/invites', { method: 'POST', headers: { authorization: 'Bearer ' + ADM, 'content-type': 'application/json' }, body: JSON.stringify({ code: inv, max_uses: 1 }) });
const browser = await chromium.launch(); const ctx = await browser.newContext({ ...devices['iPhone 13'] });
const page = await ctx.newPage(); const errs = []; page.on('pageerror', e => errs.push(e.message)); page.on('response', r => { if (r.status() === 401 && !r.url().includes('/api/login')) console.log('   401 from', r.request().method(), r.url()); });
const shot = n => page.screenshot({ path: `${OUT}/j-${n}.png`, fullPage: true });
const email = `qa+journey${Date.now()}@example.com`, pw = 'a long and memorable passphrase';
// 1. Sign up from the homepage button
await page.goto(B + '/'); await page.click('text=I have an invite code'); await page.fill('#iCode', inv); await page.click('#fInvite button');
await page.waitForSelector('#fSignup:not(.hide)'); ok(true, 'invite accepted');
await page.fill('#sName', 'Journey Tester'); await page.fill('#sEmail', email); await page.fill('#sPhone', '+971500000009');
await page.fill('#sPw', pw); await page.fill('#sPw2', pw); await page.check('#sAlpha'); await page.click('#fSignup button');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); await shot('0-2fa'); ok((await page.getAttribute('#otpLink', 'href')).startsWith('otpauth://'), 'tap-to-add authenticator link present'); const secret = (await page.textContent('#totpKey')).trim(); ok(secret.length >= 16, '2FA key shown');
await page.fill('#eCode', totp(secret)); await page.click('#fEnrol button');
await page.waitForSelector('#vRec:not(.hide)'); const codes = (await page.textContent('#vRec')).match(/[A-Z0-9]{5}-[A-Z0-9]{5}/g); ok(codes?.length === 10, '10 recovery codes shown');
ok(await page.isDisabled('#btnRecDone'), 'cannot continue until codes confirmed stored');
await page.check('#recOk'); await page.click('#btnRecDone');
// 2. Seal the vault
await page.waitForSelector('#vSeal:not(.hide)'); await page.fill('#sealTitle', 'Email login'); await page.fill('#sealBody', 'user: journey / pass: correct horse'); await page.click('#btnSeal');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok(true, 'vault sealed, dashboard shown'); await shot('1-dash');
// 3. Use the vault: letter + a second item, save
await page.fill('#letter', 'Dear family, the house deeds are with Sarah.');
await page.click('summary:has-text("Add a secret")'); await page.selectOption('#iType', 'Document location'); await page.fill('#iTitle', 'House deeds'); await page.fill('#iBody', 'Sarah Jones, solicitor'); await page.click('#btnAdd');
await page.click('#btnSave'); await page.waitForTimeout(2500); await shot('2-saved');
// 4. Nominees and rules
await page.click('[data-t=noms]'); await page.fill('#nName', 'Sam Nominee'); await page.fill('#nEmail', 'sam@example.com'); await page.fill('#nRel', 'brother'); await page.click('#btnNom');
await page.waitForSelector('#nomList .item'); ok((await page.textContent('#nomList')).includes('Sam Nominee'), 'nominee added');
await page.fill('#nName', 'Kim Nominee'); await page.fill('#nEmail', 'kim@example.com'); await page.click('#btnNom'); await page.waitForTimeout(1500);
ok((await page.$$('#nomList .item')).length === 2, 'second nominee added');
// Rehearsal: play a nominee against the interviewer
await page.click('[data-t=try]'); await page.selectOption('#tryWho', { label: 'Sam Nominee (brother)' }); await page.click('#btnTry');
await page.waitForSelector('#tryChat .bubble'); ok((await page.textContent('#tryChat')).includes('what has happened'), 'rehearsal starts with the first question');
const answers = ['Test died of a heart attack at home on 6 October 2026. I am his brother Sam.', 'It was at home in Dubai, about 7am. The ambulance took him to Mediclinic.', 'His wife and our solicitor Sarah Jones know.', 'I have the certificate from the Dubai Health Authority.', 'He was 52, born March 1974.', 'Nothing else to add.', 'Yes.', 'Yes.', 'Ok.', 'Ok.', 'Ok.', 'Ok.'];
for (const a of answers) { if (await page.isVisible('#tryResult:not(.hide)')) break; const n = (await page.$$('#tryChat .bubble')).length; await page.fill('#tryMsg', a); await page.click('#tryForm button');
  for (let w = 0; w < 120 && (await page.$$('#tryChat .bubble')).length < n + 2; w++) await page.waitForTimeout(500); }
await page.waitForSelector('#tryResult:not(.hide)', { timeout: 60000 }); ok((await page.textContent('#tryResult')).includes('what happens next'), 'rehearsal ends with the rating and next steps'); await shot('2b-rehearse');
await page.click('summary:has-text("Send us feedback")'); await page.fill('#fbText', 'Journey test feedback'); await page.click('#btnFb'); await page.waitForSelector('#fbMsg.ok'); ok(true, 'feedback sent from the app');
await page.click('[data-t=rules]'); await page.selectOption('#rDays', '180'); await page.selectOption('#rWeeks', '8'); await page.selectOption('#rVeto', '14'); await page.click('#btnRules'); await page.waitForTimeout(1500); await shot('3-rules');
const due = new Date(Date.now() + 180 * 86400000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
ok((await page.textContent('#statusLine')).includes(due), 'next check-in moves to match new frequency (' + due + ')');
if (await page.isVisible('#btnFine')) { await page.click('#btnFine'); await page.waitForTimeout(1000); ok(true, '"I\'m fine" check-in pressed'); }
// 5. Log out, log back in, check everything persisted
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)'); ok(true, 'logged out');
await page.fill('#lEmail', email); await page.fill('#lPw', pw); await page.fill('#lCode', totp(secret)); await page.click('#fLogin button');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok(true, 'logged back in with password + 2FA');
ok((await page.inputValue('#letter')).includes('house deeds'), 'letter decrypted after re-login');
const vtext = await page.textContent('#items'); ok(vtext.includes('Email login') && vtext.includes('House deeds'), 'both secrets decrypted after re-login');
await page.click('[data-t=noms]'); ok((await page.$$('#nomList .item')).length === 2, 'nominees persisted');
await page.click('[data-t=rules]'); ok(await page.inputValue('#rDays') === '180' && await page.inputValue('#rWeeks') === '8' && await page.inputValue('#rVeto') === '14', 'rules persisted');
await shot('4-relogin');
// 6. Wrong password and wrong code refused
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)');
await page.fill('#lEmail', email); await page.fill('#lPw', 'wrong password'); await page.fill('#lCode', totp(secret)); await page.click('#fLogin button'); await page.waitForTimeout(3000);
ok(!(await page.isVisible('#vDash')), 'wrong password refused');
// 7. Lost phone: recovery code, set up 2FA again, back in with vault intact
await page.goto(B + '/app'); await page.fill('#lEmail', email); await page.fill('#lPw', pw); await page.click('#toggleRec'); await page.fill('#lRec', codes[0]); await page.click('#fLogin button');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); const s2 = (await page.textContent('#totpKey')).trim(); ok(s2 !== secret, 'recovery code accepted, new 2FA key issued');
await page.fill('#eCode', totp(s2)); await page.click('#fEnrol button'); await page.waitForSelector('#vRec:not(.hide)'); await page.check('#recOk'); await page.click('#btnRecDone');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok((await page.textContent('#items')).includes('House deeds'), 'vault intact after phone recovery');
await shot('5-recovered');
console.log('page errors:', errs.length ? errs : 'none'); console.log('owner:', email);
await browser.close(); console.log(fails ? `${fails} FAILED` : 'ALL PASSED'); process.exit(fails ? 1 : 0);

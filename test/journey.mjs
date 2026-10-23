// Full owner journey in an iPhone-sized browser: sign up, use the vault, log out, log back in, lost-phone recovery
import { chromium, devices } from 'playwright'; import crypto from 'crypto';
const B = process.env.B || 'http://localhost:8787', ADM = process.env.ADM || 'admin-dev-token', OUT = process.env.OUT || 'shots';

// Production guard: refuse to run tests against non-localhost unless explicitly allowed
const u = new URL(B);
if (!['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && process.env.ALLOW_LIVE !== 'yes-i-mean-production') {
  console.error(`HARD RULE: Tests must not run against ${B}. Only localhost/127.0.0.1/[::1] are allowed, or set ALLOW_LIVE=yes-i-mean-production.`);
  process.exit(1);
}

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
// 0. Homepage: the request-access box is clearly the visitor's own email
await page.goto(B + '/'); ok((await page.textContent('label[for=wlEmail]')).trim() === 'Your email' && await page.isVisible('label[for=wlEmail]') && !(await page.getAttribute('#wlEmail', 'placeholder')), 'homepage request-access box is labelled "Your email", with no placeholder');
// 1. Sign up via the discreet 'Have an invite code?' link on /app (the homepage no longer has an invite-code button)
await page.goto(B + '/app'); await page.click('#vAuth .tabs [data-t=signup]'); await page.click('#showCodeLink'); await page.fill('#iCode', inv); await page.click('#fInvite button');
await page.waitForSelector('#fSignup:not(.hide)'); ok(true, 'invite accepted');
await page.fill('#sName', 'Journey Tester'); await page.fill('#sEmail', email); await page.click('#sPhone'); await page.keyboard.type('+971 50 000 0009'); ok(await page.inputValue('#sPhone') === '+971 50 000 0009', 'typing + into the phone field does not double it');
ok((await page.textContent('#sPhoneHint')).includes('Include country code') && !(await page.getAttribute('#sPhone', 'placeholder')), 'mobile hint under the label, not inside the box');
// Phone: lenient, checked on blur; 00 becomes +; a local number gets a friendly message; empty is fine
await page.fill('#sPhone', '07700 900123'); ok(!(await page.textContent('#sPhoneMsg')), 'no phone message while typing');
await page.click('#sName'); ok((await page.textContent('#sPhoneMsg')).includes('country code'), 'local-format mobile: friendly country-code message on blur');
await page.fill('#sPhone', '0044 (7700) 900-123'); await page.click('#sName'); ok(await page.inputValue('#sPhone') === '+44 (7700) 900-123' && !(await page.textContent('#sPhoneMsg')), '00 at the start becomes +, brackets and dashes accepted');
await page.fill('#sPhone', '+971 50 000 0009'); await page.click('#sName');
// Password: rules shown up front, show/hide toggles, live match indicator
ok((await page.textContent('#sPwHint')).includes('At least 12 characters'), 'password rules shown up front');
await page.fill('#sPw', pw); await page.fill('#sPw2', pw.slice(0, 5)); ok((await page.textContent('#pwMatch')).includes("don't match") && await page.getAttribute('#pwMatch', 'class').then(c => c.includes('bad')), 'confirm field shows a cross and text while passwords differ');
await page.click('.eye[data-for=sPw]'); ok(await page.getAttribute('#sPw', 'type') === 'text' && await page.getAttribute('.eye[data-for=sPw]', 'aria-pressed') === 'true' && await page.getAttribute('.eye[data-for=sPw]', 'aria-label') === 'Show password', 'eye button shows the password (aria-pressed true)');
await page.click('.eye[data-for=sPw]'); ok(await page.getAttribute('#sPw', 'type') === 'password' && await page.getAttribute('.eye[data-for=sPw]', 'aria-pressed') === 'false', 'eye button hides it again');
ok(await page.getAttribute('.eye[data-for=sPw2]', 'aria-label') === 'Show confirm password', 'confirm field has its own eye button');
await page.fill('#sPw', pw); await page.fill('#sPw2', pw); ok((await page.textContent('#pwMatch')).includes('\u2713 Passwords match'), 'confirm field shows a tick and text when they match'); await page.check('#sAlpha'); await page.click('#fSignup button.accent');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }).catch(async e => { console.log('   flash:', await page.textContent('#flash')); throw e; }); await shot('0-2fa'); ok((await page.getAttribute('#otpLink', 'href')).startsWith('otpauth://'), 'tap-to-add authenticator link present'); ok((await page.getAttribute('#otpLink', 'href')).includes('&image=https%3A%2F%2Fsavemysecrets.com%2Ftotp-logo.png'), 'otpauth link includes the logo image param'); ok(await page.locator('#qr canvas, #qr img').count() > 0, 'QR code rendered'); const secret = (await page.textContent('#totpKey')).trim(); ok(secret.length >= 16, '2FA key shown');
ok(await page.isVisible('#skipLink') && (await page.textContent('#skipLink')).trim() === 'Skip for now (not recommended)', 'signup enrol screen offers the skip option');
ok(await page.evaluate(() => { const s = document.getElementById('skipLink'), p = document.querySelector('#fEnrol button[type=submit]'); return s.tagName === 'BUTTON' && s.classList.contains('ghost') && s.parentElement === p.parentElement; }), 'skip is a secondary button beside "Turn on two-factor"'); ok(!(await page.isVisible('#skipConfirm')), 'skip confirm hidden until asked');
await page.fill('#eCode', totp(secret)); await page.click('#fEnrol button');
await page.waitForSelector('#vRec:not(.hide)'); const codes = (await page.textContent('#vRec')).match(/[A-Z0-9]{5}-[A-Z0-9]{5}/g); ok(codes?.length === 10, '10 recovery codes shown');
ok(await page.isDisabled('#btnRecDone'), 'cannot continue until codes confirmed stored');
await page.check('#recOk'); await page.click('#btnRecDone');
// 2. Seal the vault
await page.waitForSelector('#vSeal:not(.hide)'); await shot('1a-first-secret'); ok(await page.getAttribute('#sealTitle', 'placeholder') === null && (await page.locator('#sealBody').boundingBox()).height >= 200 && await page.locator('#extraCode').count() === 0, 'first-secret form: no title placeholder, larger details box, no printed-code option'); await page.fill('#sealTitle', 'Email login'); await page.fill('#sealBody', 'user: journey / pass: correct horse'); await page.click('#btnSeal');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok(true, 'vault sealed, dashboard shown'); await shot('1-dash');
ok(!(await page.isVisible('#tfaBanner')), 'no 2FA banner when 2FA is on');
// 3. Use the vault: a second item, save. The letter field is gone; simulate a vault saved before then, which has a letter
ok(await page.locator('#letter').count() === 0 && !/Letter to your nominees/.test(await page.textContent('#vDash')), 'no letter field on the vault screen');
// Also an older secret saved with a type label, from before the Type dropdown was removed
await page.evaluate(async () => { vault.letter = 'Dear family, the house deeds are with Sarah.'; vault.items.push({ type: 'Password / login', title: 'Old bank login', body: 'barclays / see the safe' }); await post('/api/me/vault', { vault: await SMS.encVault(K, vault), wrappedOwner: await SMS.seal(ownerKey, K) }); });
await page.click('summary:has-text("Add a secret")'); ok(await page.locator('#iType').count() === 0 && !/>Type</.test(await page.innerHTML('#tVault')), 'Add a secret has no Type dropdown'); await page.fill('#iTitle', 'House deeds'); await page.fill('#iBody', 'Sarah Jones, solicitor'); await page.click('#btnAdd');
await page.click('#btnSave'); await page.waitForTimeout(2500); await shot('2-saved');
// 4. Nominees and rules. Each nominee is added together with their three questions; we never hold a copy of the key
await page.click('[data-t=noms]'); await page.fill('#nName', 'Sam Nominee'); await page.fill('#nEmail', 'sam@example.com'); await page.fill('#nRel', 'brother');
ok((await page.textContent('#tNoms')).includes("Pick questions only your nominee could answer, not things someone could guess or look up online, like a pet's name."), 'gentle warning shown on the questions screen');
ok(await page.evaluate(() => [...document.querySelectorAll('#tNoms input, #tNoms textarea')].filter(e => e.placeholder).map(e => e.id)).then(x => x.length === 0), 'no example placeholders on the nominee or question fields');
await page.click('#btnNom'); await page.waitForTimeout(500);
ok((await page.textContent('#nMsg')).includes('Write all three questions') && (await page.$$('#nomList .item')).length === 0, 'a nominee cannot be added without their questions');
const fillNew = async (who, ans) => { for (let i = 0; i < 3; i++) { await page.fill('#nq' + i, `Question ${i + 1} for ${who}?`); await page.fill('#na' + i, ans[i]); } };
await fillNew('Sam Nominee', ['Marbella', 'Sea Biscuit', 'Mrs Okafor']); await page.fill('#nx0', 'Puerto Banus');
await page.locator('#btnNom').scrollIntoViewIfNeeded(); await page.screenshot({ path: process.env.ADDNOM_SHOT || `${OUT}/j-2c-add-nominee.png`, fullPage: true });
await page.click('#btnNom'); await page.waitForSelector('#nomList .item', { timeout: 60000 }); ok((await page.textContent('#nomList')).includes('Sam Nominee'), 'nominee added with their questions');
ok((await page.inputValue('#nName')) === '' && (await page.inputValue('#nq0')) === '', 'add form cleared for the next nominee');
ok(!(await page.isVisible('#nomAdd')) && await page.isVisible('#btnAddAnother') && (await page.textContent('#nomOneNote')).includes('One nominee is enough. You can add more as backups.'), 'after saving, the add form folds away: list, "one is enough" note and "Add another nominee" button');
await page.click('#btnAddAnother'); ok(await page.isVisible('#nomAdd') && (await page.textContent('#nomAddHead')) === 'Add another nominee' && !(await page.isVisible('#btnAddAnother')), '"Add another nominee" opens the form');
await page.fill('#nName', 'Kim Nominee'); await page.fill('#nEmail', 'kim@example.com'); await fillNew('Kim Nominee', ['Rome', 'Bluebell', 'Mr Jones']); await page.click('#btnNom');
await page.waitForFunction(() => document.querySelectorAll('#nomList .item').length === 2, null, { timeout: 60000 });
ok((await page.$$('#nomList .item')).length === 2, 'second nominee added');
// Change one nominee's questions later
await page.locator('#nomList .item', { hasText: 'Kim Nominee' }).locator('button', { hasText: /questions/ }).click(); ok(await page.isVisible('#qEdit'), 'change-questions form opens');
ok(await page.evaluate(() => [0, 1, 2].every(i => !document.getElementById('qq' + i).placeholder && !document.getElementById('qa' + i).placeholder)), 'Questions for <name>: no example placeholders');
for (let i = 0; i < 3; i++) { await page.fill('#qq' + i, `New question ${i + 1}?`); await page.fill('#qa' + i, ['Paris', 'Daisy', 'Mrs Lee'][i]); }
await page.click('#btnQSave'); await page.waitForSelector('#qEdit.hide', { state: 'attached', timeout: 60000 });
await page.waitForTimeout(800); await shot('2a-questions');
ok((await page.textContent('#qBanner')).includes('We never hold a key to your vault'), 'banner says we never hold a key');
ok((await page.textContent('#nomList')).split('Questions set').length === 3 && !(await page.textContent('#nomList')).includes('Not set up') && !(await page.isVisible('#notSetBanner')), 'both nominees set up, no warning');
ok(!(await page.evaluate(() => me.hasRelease)), 'dashboard data: no release copy held');
// Rehearsal: play a nominee against the interviewer
await page.click('[data-t=try]'); await page.selectOption('#tryWho', { label: 'Sam Nominee (brother)' }); await page.click('#btnTry');
await page.waitForSelector('#tryChat .bubble'); ok((await page.textContent('#tryChat')).includes('what has happened'), 'rehearsal starts with the first question');
const answers = ['Test died of a heart attack at home on 6 October 2026. I am his brother Sam.', 'It was at home in Dubai, about 7am. The ambulance took him to Mediclinic.', 'His wife and our solicitor Sarah Jones know.', 'I have the certificate from the Dubai Health Authority.', 'He was 52, born March 1974.', 'Nothing else to add.', 'Yes.', 'Yes.', 'Ok.', 'Ok.', 'Ok.', 'Ok.'];
for (const a of answers) { if (await page.isVisible('#tryResult:not(.hide)')) break; const n = (await page.$$('#tryChat .bubble')).length; await page.fill('#tryMsg', a); await page.click('#tryForm button');
  for (let w = 0; w < 120 && (await page.$$('#tryChat .bubble')).length < n + 2; w++) await page.waitForTimeout(500); }
await page.waitForSelector('#tryResult:not(.hide)', { timeout: 60000 }); ok((await page.textContent('#tryResult')).includes('what happens next'), 'rehearsal ends with the rating and next steps'); await shot('2b-rehearse');
await page.click('summary:has-text("Send us feedback")'); await page.fill('#fbText', 'Journey test feedback'); await page.click('#btnFb'); await page.waitForSelector('#fbMsg.ok'); ok(true, 'feedback sent from the app');
await page.click('[data-t=rules]');
ok((await page.textContent('#rulesOrder')).includes('Only after that do we contact your nominees') && (await page.textContent('label[for=rVeto]')).includes('last window to respond'), 'Rules explain the release order; the final check is your last window to respond');
// A local-format mobile is caught before saving, right by the button, and nothing is half-saved
await page.fill('#rPhone', '07700 900123'); await page.click('#btnRules');
ok((await page.textContent('#rPhoneMsg')).includes('country code') && (await page.textContent('#rMsg')).includes('Not saved yet'), 'bad mobile on Rules: inline message, and the save is clearly not done');
await page.fill('#rPhone', '0044 7700 900123'); await page.selectOption('#rDays', '60'); await page.selectOption('#rWeeks', '2'); await page.selectOption('#rVeto', '14'); await page.click('#btnRules');
await page.waitForFunction(() => document.getElementById('rMsg').textContent.includes('Rules saved'), null, { timeout: 15000 });
ok(await page.locator('#rMsg').evaluate(e => { const r = e.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; }) && (await page.evaluate(() => me.phone)) === '+447700900123', 'Lilian\'s rules (2 months, 2 weeks, 14 days) save, with "Rules saved" in view by the button; mobile stored as +447700900123');
ok(await page.evaluate(() => me.policy.checkin_days === 60 && me.policy.grace_weeks === 2 && me.policy.veto_days === 14), 'those values are stored');
await page.fill('#rPhone', ''); await page.selectOption('#rDays', '180'); await page.selectOption('#rWeeks', '8'); await page.selectOption('#rVeto', '14'); await page.click('#btnRules');
await page.waitForFunction(() => document.getElementById('rMsg').textContent.includes('Rules saved'), null, { timeout: 15000 }); await shot('3-rules');
ok((await page.evaluate(() => me.phone)) === null, 'an empty mobile never blocks saving, and clearing it removes the number');
const due = new Date(Date.now() + 180 * 86400000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
ok((await page.textContent('#statusLine')).includes(due), 'next check-in moves to match new frequency (' + due + ')');
ok((await page.textContent('#statusLine')).includes('All good') && !(await page.isVisible('#btnFine')), 'all good and check-in in the future: no "I\'m fine" button');
await page.locator('.card:has(#statusLine)').screenshot({ path: process.env.STATUS_SHOT || `${OUT}/j-3a-status-no-button.png` });
// Miss a check-in (local escalation run, 181 days on): the button appears, and tapping it puts things right
await fetch(B + '/api/admin/run-escalation', { method: 'POST', headers: { authorization: 'Bearer ' + ADM, 'content-type': 'application/json' }, body: JSON.stringify({ at: Date.now() + 181 * 86400000, emails: [email] }) });
await page.evaluate(async () => { me = await call('/api/me'); renderAll(); });
ok((await page.textContent('#statusLine')).includes('You missed a check-in') && await page.isVisible('#btnFine'), 'missed check-in: "I\'m fine" button shown');
await page.click('#btnFine'); await page.waitForFunction(() => document.getElementById('btnFine').classList.contains('hide'), null, { timeout: 15000 });
ok((await page.textContent('#statusLine')).includes('All good'), '"I\'m fine" check-in pressed; back to all good and the button hides');
// 5. Log out, log back in, check everything persisted
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)'); ok(true, 'logged out');
await page.fill('#lEmail', email); await page.fill('#lPw', pw); await page.fill('#lCode', totp(secret)); await page.click('#fLogin button');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok(true, 'logged back in with password + 2FA');
ok((await page.evaluate(() => vault.letter)) === 'Dear family, the house deeds are with Sarah.', 'existing letter kept after adding a secret and saving, and after re-login');
const vtext = await page.textContent('#items'); ok(vtext.includes('Email login') && vtext.includes('House deeds'), 'both secrets decrypted after re-login');
ok(vtext.includes('Old bank login') && vtext.includes('Password / login') && vtext.includes('barclays / see the safe'), 'an older typed secret still shows, with its type label');
{ const its = await page.evaluate(() => vault.items); ok(its.find(i => i.title === 'House deeds')?.type === undefined && its.find(i => i.title === 'Email login')?.type === undefined, 'new secrets are stored as title and details only'); }
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
ok(!(await page.isVisible('#skipLink')), 'no skip option when re-enrolling after a recovery code');
await page.fill('#eCode', totp(s2)); await page.click('#fEnrol button'); await page.waitForSelector('#vRec:not(.hide)'); await page.check('#recOk'); await page.click('#btnRecDone');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok((await page.textContent('#items')).includes('House deeds'), 'vault intact after phone recovery');
await shot('5-recovered');
// 8. Optional 2FA: skip at signup, password-only login, then turn 2FA on later from the dashboard
const inv2 = 'JOURNEYSKIP' + Date.now();
await fetch(B + '/api/admin/invites', { method: 'POST', headers: { authorization: 'Bearer ' + ADM, 'content-type': 'application/json' }, body: JSON.stringify({ code: inv2, max_uses: 1 }) });
const email2 = `qa+skip${Date.now()}@example.com`;
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)');
await page.goto(B + '/app?invite=' + inv2 + '&email=' + encodeURIComponent(email2)); await page.waitForSelector('#fSignup:not(.hide)');
await page.fill('#sName', 'Skip Tester'); await page.fill('#sPw', pw); await page.fill('#sPw2', pw); await page.check('#sAlpha'); await page.click('#fSignup button.accent');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); await page.locator('#skipLink').scrollIntoViewIfNeeded(); await page.screenshot({ path: `${OUT}/j-6-skip-link.png` });
await page.click('#skipLink'); await page.waitForSelector('#skipConfirm:not(.hide)');
ok((await page.textContent('#skipConfirm')).includes('Without 2FA, anyone who learns your password can open your vault. You can turn 2FA on later from your dashboard.'), 'skip confirm explains the risk');
ok((await page.textContent('#btnSkipYes')).trim() === 'Skip anyway' && (await page.textContent('#btnSkipNo')).trim() === 'Set up 2FA', 'skip confirm buttons');
await page.locator('#skipConfirm').scrollIntoViewIfNeeded(); await page.screenshot({ path: `${OUT}/j-7-skip-confirm.png` });
await page.click('#btnSkipNo'); ok(!(await page.isVisible('#skipConfirm')) && await page.isVisible('#vEnrol'), '"Set up 2FA" goes back to the enrol screen');
await page.click('#skipLink'); await page.click('#btnSkipYes');
await page.waitForSelector('#vSeal:not(.hide)', { timeout: 30000 }); ok(!(await page.isVisible('#vRec')), 'skipping shows no recovery codes step');
await page.fill('#sealTitle', 'Skip test'); await page.fill('#sealBody', 'hello'); await page.click('#btnSeal');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 });
ok(await page.isVisible('#tfaBanner') && (await page.textContent('#tfaBanner')).includes('Your vault is protected by your password only. Turn on 2FA'), 'dashboard shows the 2FA banner');
ok(!(await page.textContent('#statusLine')).includes('no recovery codes left'), 'no "no recovery codes left" warning without 2FA');
await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: `${OUT}/j-8-banner.png` });
// Password-only login after skipping
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)');
await page.fill('#lEmail', email2); await page.fill('#lPw', pw); await page.click('#fLogin button');
await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok((await page.textContent('#items')).includes('Skip test'), 'skipped account logs in with password only, vault decrypts');
// Settings: set up 2FA
await page.click('[data-t=rules]'); ok(await page.isVisible('#btnTfaSetup'), 'settings offer "Set up 2FA"');
await page.locator('#tfaSettings').scrollIntoViewIfNeeded(); await page.screenshot({ path: `${OUT}/j-9-settings-setup.png` });
await page.click('#btnTfaSetup'); await page.waitForSelector('#vEnrol:not(.hide)');
ok(!(await page.isVisible('#skipLink')), 'no skip link when setting up from settings');
ok((await page.getAttribute('#otpLink', 'href')).includes('&image=https%3A%2F%2Fsavemysecrets.com%2Ftotp-logo.png') && await page.locator('#qr canvas, #qr img').count() > 0, 'settings setup shows the QR and logo URI');
await page.screenshot({ path: `${OUT}/j-10-settings-enrol.png` });
const s3 = (await page.textContent('#totpKey')).trim();
await page.fill('#eCode', totp(s3)); await page.click('#fEnrol button'); await page.waitForSelector('#vRec:not(.hide)');
ok(((await page.textContent('#vRec')).match(/[A-Z0-9]{5}-[A-Z0-9]{5}/g) || []).length === 10, 'recovery codes shown after turning 2FA on later');
await page.check('#recOk'); await page.click('#btnRecDone'); await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 });
ok(!(await page.isVisible('#tfaBanner')), 'banner gone once 2FA is on'); await page.click('[data-t=rules]'); ok(!(await page.isVisible('#tfaSettings')), 'settings setup hidden once 2FA is on');
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)');
await page.fill('#lEmail', email2); await page.fill('#lPw', pw); await page.click('#fLogin button'); await page.waitForTimeout(3000);
ok(!(await page.isVisible('#vDash')) && (await page.textContent('#flash')).includes('Two-factor code incorrect'), 'after turning 2FA on, the code is required');
await page.fill('#lCode', totp(s3)); await page.click('#fLogin button'); await page.waitForSelector('#vDash:not(.hide)', { timeout: 30000 }); ok(true, 'logged in with password + new 2FA code');
// 9. Used invite link: leave at the 2FA screen, reopen the email link, land on Log in and resume enrolment
const inv3 = 'JOURNEYUSED' + Date.now(), email3 = `qa+used${Date.now()}@example.com`;
await fetch(B + '/api/admin/invites', { method: 'POST', headers: { authorization: 'Bearer ' + ADM, 'content-type': 'application/json' }, body: JSON.stringify({ code: inv3, max_uses: 1 }) });
await page.click('#logout'); await page.waitForSelector('#vAuth:not(.hide)');
const link3 = B + '/app?code=' + inv3 + '&email=' + encodeURIComponent(email3);
await page.goto(link3); await page.waitForSelector('#fSignup:not(.hide)'); ok(await page.inputValue('#sEmail') === email3, 'invite link prefills signup email');
ok(!(await page.isVisible('#iCode')) && !(await page.isVisible('#fInvite')) && !/invite code/i.test(await page.locator('#vAuth').innerText()), 'email link lands on Create vault with no invite-code field or wording');
await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: process.env.FRESH_SHOT || `${OUT}/j-11a-link-fresh.png` });
await page.fill('#sName', 'Used Link Tester'); await page.fill('#sPw', pw); await page.fill('#sPw2', pw); await page.check('#sAlpha'); await page.click('#fSignup button.accent');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); ok(true, 'account created, left at the 2FA screen');
await page.goto(link3); await page.waitForFunction(() => document.getElementById('flash').textContent.includes('already have an account'), null, { timeout: 15000 });
ok(await page.isVisible('#fLogin') && !(await page.isVisible('#fSignup')) && !(await page.isVisible('#fInvite')), 'used invite link opens the Log in tab');
ok(await page.inputValue('#lEmail') === email3, 'used invite link prefills the login email');
ok((await page.textContent('#flash')).trim() === 'You already have an account. Log in to carry on.' && (await page.getAttribute('#flash', 'class')) === 'notice' && !/invite/i.test(await page.locator('#vAuth').innerText()), 'friendly neutral notice, not a red error, and no invite wording');
await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: process.env.USED_SHOT || `${OUT}/j-11-used-link-login.png` });
await page.fill('#lPw', pw); await page.click('#fLogin button');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); ok(await page.isVisible('#skipLink'), 'logging in resumes enrolment, with skip available');
console.log('page errors:', errs.length ? errs : 'none'); console.log('owner:', email);
await browser.close(); console.log(fails ? `${fails} FAILED` : 'ALL PASSED'); process.exit(fails ? 1 : 0);

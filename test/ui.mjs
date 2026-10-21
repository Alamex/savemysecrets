import { chromium, devices } from 'playwright'; import crypto from 'crypto'; import fs from 'fs';
const B = process.env.B || 'http://localhost:8787', ADM = process.env.ADM || 'admin-dev-token', P = B.startsWith('https') ? 'live-' : '';

// Production guard: refuse to run tests against non-localhost unless explicitly allowed
const u = new URL(B);
if (!['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && process.env.ALLOW_LIVE !== 'yes-i-mean-production') {
  console.error(`HARD RULE: Tests must not run against ${B}. Only localhost/127.0.0.1/[::1] are allowed, or set ALLOW_LIVE=yes-i-mean-production.`);
  process.exit(1);
}

function totp(secret) { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of secret.replace(/\s/g, '')) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4); const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0'); }
const browser = await chromium.launch();
const ctx = await browser.newContext({ ...devices['iPhone 13'], acceptDownloads: true });
const page = await ctx.newPage(); const errs = []; page.on('pageerror', e => errs.push(e.message));
await page.goto(B + '/'); await page.screenshot({ path: 'shots/' + P + '1-landing.png' });
await page.screenshot({ path: 'shots/' + P + '1b-landing-full.png', fullPage: true });
await page.fill('#wlEmail', 'ui' + Date.now() + '@x.com'); await page.click('#wl button[type=submit]'); await page.waitForSelector('#wlMsg.ok'); 
await page.goto(B + '/app?invite=testconf'); await page.waitForTimeout(300); await page.screenshot({ path: 'shots/' + P + '1c-invite.png' }); await page.click('#fInvite button'); await page.waitForSelector('#fSignup:not(.hide)');
const ownerEmail = `ui${Date.now()}@x.com`; await page.fill('#sName', 'Ui Tester'); await page.fill('#sEmail', ownerEmail); await page.fill('#sPhone', '+971500000001');
await page.fill('#sPw', 'a very long password'); await page.fill('#sPw2', 'a very long password'); await page.check('#sAlpha'); await page.screenshot({ path: 'shots/' + P + '1d-signup.png', fullPage: true }); await page.click('#fSignup button');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); await page.screenshot({ path: 'shots/' + P + '2-2fa.png' });
await page.fill('#eCode', totp(await page.textContent('#totpKey'))); await page.click('#fEnrol button');
await page.waitForSelector('#vRec:not(.hide)'); await page.screenshot({ path: 'shots/' + P + '2b-recovery.png', fullPage: true });
console.log('recovery codes shown:', (await page.textContent('#vRec')).match(/[A-Z0-9]{5}-[A-Z0-9]{5}/g)?.length);
await page.check('#recOk'); await page.click('#btnRecDone');
await page.waitForSelector('#vSeal:not(.hide)'); await page.fill('#sealTitle', 'Ledger backup location'); await page.fill('#sealBody', 'Steel plate in the safe, bottom drawer.');
await page.screenshot({ path: 'shots/' + P + '3-seal.png' }); await page.click('#btnSeal');
await page.waitForSelector('#vDash:not(.hide)');
const code = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH';
await page.screenshot({ path: 'shots/' + P + '5-dash.png' });
await page.click('[data-t=noms]'); await page.fill('#nName', 'Ané'); await page.fill('#nEmail', 'nom@x.com'); await page.fill('#nRel', 'wife'); await page.click('#btnNom');
await page.waitForSelector('#nomList .item'); await page.screenshot({ path: 'shots/' + P + '6-nominees.png' });
await page.click('[data-t=rules]'); await page.screenshot({ path: 'shots/' + P + '7-rules.png' });
const cp = await ctx.newPage(); await cp.goto(B + '/claim'); await cp.screenshot({ path: 'shots/' + P + '9-claim.png' });
await cp.fill('#cName', 'Ui Nominee'); await cp.fill('#cEmail', 'nom@x.com'); await cp.click('#f1 button'); await cp.waitForSelector('#s2:not(.hide)');
const ev = await (await fetch(B + '/api/admin/events', { headers: { authorization: 'Bearer ' + ADM + '' } })).json();
const otp = JSON.parse(ev.find(e => e.detail.includes('verification code') && e.detail.includes('nom@x.com')).detail).html.match(/<b>(\d{6})<\/b>/)[1];
await cp.screenshot({ path: 'shots/' + P + '9b-claim-code.png' }); await cp.fill('#cCode', otp); await cp.click('#f2 button');
await cp.waitForSelector('#sFind:not(.hide)'); await cp.screenshot({ path: 'shots/' + P + '9c-claim-find.png' });
await cp.fill('#oEmail', ownerEmail); await cp.click('#fFind button'); await cp.waitForSelector('#s3:not(.hide) .bubble'); await cp.screenshot({ path: 'shots/' + P + '9d-claim-chat.png' });
await page.goto(B + '/app'); await page.waitForTimeout(800); await page.screenshot({ path: 'shots/' + P + '9e-owner-alert.png' });
const sp = await ctx.newPage(); for (const pg of ['privacy', 'terms', 'preview']) { await sp.goto(B + '/' + pg); await sp.screenshot({ path: `shots/${P}10-${pg}.png`, fullPage: true }); console.log(pg, 'overflow', await sp.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)); }
await sp.goto(B + '/preview'); await sp.click('#toNominee'); for (const a of ['Puerto Banus', 'seabiscuit', 'okafor']) { if (await sp.isVisible('#ansIn')) { await sp.fill('#ansIn', a); await sp.click('#ans button'); await sp.waitForTimeout(700); } }
await sp.waitForTimeout(800); await sp.screenshot({ path: 'shots/' + P + '10b-preview-answers.png', fullPage: true });
// horizontal overflow check on every page
for (const p of [page, cp]) { const w = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth); console.log('overflow px', p.url(), w); }
await page.goto(B + '/'); console.log('landing overflow', await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth));
console.log('page errors:', errs.length ? errs : 'none');
await browser.close();

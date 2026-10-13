import { chromium, devices } from 'playwright'; import crypto from 'crypto'; import fs from 'fs';
const B = 'http://localhost:8787';
function totp(secret) { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of secret.replace(/\s/g, '')) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4); const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0'); }
const browser = await chromium.launch();
const ctx = await browser.newContext({ ...devices['iPhone 13'], acceptDownloads: true });
const page = await ctx.newPage(); const errs = []; page.on('pageerror', e => errs.push(e.message));
await page.goto(B + '/'); await page.screenshot({ path: 'shots/1-landing.png' });
await page.screenshot({ path: 'shots/1b-landing-full.png', fullPage: true });
await page.fill('#wlEmail', 'ui' + Date.now() + '@x.com'); await page.click('#wl button[type=submit]'); await page.waitForSelector('#wlMsg.ok'); 
await page.goto(B + '/app?invite=testconf'); await page.waitForTimeout(300); await page.screenshot({ path: 'shots/1c-invite.png' }); await page.click('#fInvite button'); await page.waitForSelector('#fSignup:not(.hide)');
await page.fill('#sName', 'Ui Tester'); await page.fill('#sEmail', `ui${Date.now()}@x.com`); await page.fill('#sPhone', '+971500000001');
await page.fill('#sPw', 'a very long password'); await page.fill('#sPw2', 'a very long password'); await page.check('#sAlpha'); await page.screenshot({ path: 'shots/1d-signup.png', fullPage: true }); await page.click('#fSignup button');
await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 30000 }); await page.screenshot({ path: 'shots/2-2fa.png' });
await page.fill('#eCode', totp(await page.textContent('#totpKey'))); await page.click('#fEnrol button');
await page.waitForSelector('#vSeal:not(.hide)'); await page.fill('#sealTitle', 'Ledger backup location'); await page.fill('#sealBody', 'Steel plate in the safe, bottom drawer.');
await page.screenshot({ path: 'shots/3-seal.png' }); await page.click('#btnSeal');
await page.waitForSelector('#vDash:not(.hide)');
const code = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH';
await page.screenshot({ path: 'shots/5-dash.png' });
await page.click('[data-t=noms]'); await page.fill('#nName', 'Ané'); await page.fill('#nEmail', 'nom@x.com'); await page.fill('#nRel', 'wife'); await page.click('#btnNom');
await page.waitForSelector('#nomList .item'); await page.screenshot({ path: 'shots/6-nominees.png' });
await page.click('[data-t=rules]'); await page.screenshot({ path: 'shots/7-rules.png' });
const cp = await ctx.newPage(); await cp.goto(B + '/claim?u=x'); await cp.screenshot({ path: 'shots/9-claim.png' });
// horizontal overflow check on every page
for (const p of [page, cp]) { const w = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth); console.log('overflow px', p.url(), w); }
await page.goto(B + '/'); console.log('landing overflow', await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth));
console.log('page errors:', errs.length ? errs : 'none');
await browser.close();

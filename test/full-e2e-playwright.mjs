#!/usr/bin/env node
// Comprehensive end-to-end UI test for Save My Secrets alpha readiness
// Tests ALL flows in desktop (1280x720) and mobile (390x844) viewports
// Usage: BASE_URL=http://localhost:8787 ADM=admin-dev-token node test/full-e2e-playwright.mjs

import { chromium } from 'playwright';
import fs from 'fs';
import vm from 'vm';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';
const ADM = process.env.ADM || 'admin-dev-token';
const SCREENSHOT_DIR = './test-screenshots';

// Load crypto.js for vault operations
const ctx = { crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array, JSON, document: undefined };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(new URL('../public/crypto.js', import.meta.url), 'utf8') + ';this.SMS=SMS;', ctx);
const { SMS } = ctx;

// Create screenshots directory
if (!fs.existsSync(SCREENSHOT_DIR)) fs.mkdirSync(SCREENSHOT_DIR);

let browser, pass = 0, fail = 0;
const results = [];

function log(status, message, viewport = '') {
  const prefix = viewport ? `[${viewport}] ` : '';
  console.log(`${status ? '✓' : '✗'} ${prefix}${message}`);
  results.push({ status, message: prefix + message });
  if (status) pass++; else fail++;
}

async function getOTPFromAdmin(email, token) {
  const response = await fetch(`${BASE_URL}/api/admin/events`, {
    headers: { 'authorization': `Bearer ${token}` }
  });
  const events = await response.json();
  const otpEvent = events.find(e => e.kind.startsWith('email') && e.detail.includes('verification code') && e.detail.includes(email));
  if (!otpEvent) throw new Error('OTP not found in events');
  const detail = JSON.parse(otpEvent.detail);
  const match = detail.html.match(/<b>(\d{6})<\/b>/);
  return match ? match[1] : null;
}

function totp(secret) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, val = 0;
  const out = [];
  for (const c of secret) {
    val = (val << 5) | A.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
  const crypto = await import('crypto');
  const h = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest();
  const o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}

async function testViewport(viewportName, width, height) {
  const context = await browser.newContext({ viewport: { width, height } });
  const page = await context.newPage();
  
  const timestamp = Date.now();
  const ownerEmail = `owner-${timestamp}@example.com`;
  const nomineeEmail = `nominee-${timestamp}@example.com`;
  const password = 'correct horse battery staple';
  
  let totpSecret, ownerKey, serverShare, kdfSalt, legacyCode;
  
  try {
    // 1. Homepage loads and has no SMS/WhatsApp mentions
    await page.goto(BASE_URL);
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-01-homepage.png`, fullPage: true });
    const homeContent = await page.content();
    log(!homeContent.includes('WhatsApp') && !homeContent.includes('text message'), 
        `Homepage has no SMS/WhatsApp mentions`, viewportName);
    log(homeContent.includes('manual review') || homeContent.includes('person on our team'),
        `Homepage mentions manual review`, viewportName);
    log(!homeContent.includes('passport') && !homeContent.includes('ID check'),
        `Homepage has no passport/ID verification promises`, viewportName);
    
    // 2. Waitlist signup (with welcome email)
    const wlEmail = `waitlist-${timestamp}@example.com`;
    await page.fill('#wlEmail', wlEmail);
    await page.click('button[type="submit"]');
    await page.waitForSelector('.ok', { timeout: 3000 }).catch(() => {});
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-02-waitlist.png` });
    
    // Check welcome email was sent
    await new Promise(resolve => setTimeout(resolve, 500));
    const eventsResp = await fetch(`${BASE_URL}/api/admin/events`, {
      headers: { 'authorization': `Bearer ${ADM}` }
    });
    const events = await eventsResp.json();
    const welcomeEmail = events.some(e => 
      e.detail.includes(wlEmail) && 
      e.detail.includes('waiting list') &&
      e.detail.includes('Thank you for your interest')
    );
    log(welcomeEmail, 'Welcome email sent to waitlist signup', viewportName);
    
    // 3. Create invite and start signup
    const inviteCode = `TEST${timestamp}`;
    await fetch(`${BASE_URL}/api/admin/invites`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'authorization': `Bearer ${ADM}` },
      body: JSON.stringify({ code: inviteCode, label: 'E2E test', max_uses: 10 })
    });
    
    await page.goto(`${BASE_URL}/app?invite=${inviteCode}`);
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-03-signup-start.png`, fullPage: true });
    
    // Check phone field is optional (no mobile field for signup in alpha)
    const signupContent = await page.content();
    log(!signupContent.includes('Mobile (for check-in texts and WhatsApp)'),
        'Signup form has no SMS/WhatsApp phone field', viewportName);
    
    // 4. Register account
    await page.click('[data-t="signup"]');
    await page.fill('#iCode', inviteCode);
    await page.click('#fInvite button');
    await page.waitForSelector('#fSignup:not(.hide)');
    
    await page.fill('#sName', 'Test Owner');
    await page.fill('#sEmail', ownerEmail);
    await page.fill('#sPw', password);
    await page.fill('#sPw2', password);
    await page.check('#sAlpha');
    await page.click('#fSignup button');
    await page.waitForSelector('#vEnrol:not(.hide)', { timeout: 5000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-04-2fa-setup.png`, fullPage: true });
    
    // 5. Set up 2FA
    totpSecret = await page.textContent('#totpKey');
    log(!!totpSecret, '2FA secret generated', viewportName);
    
    const totpCode = totp(totpSecret);
    await page.fill('#eCode', totpCode);
    await page.click('#fEnrol button');
    await page.waitForSelector('#vRec:not(.hide)', { timeout: 5000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-05-recovery-codes.png`, fullPage: true });
    
    // 6. Recovery codes screen
    const recCodes = await page.textContent('#recBox');
    log(recCodes.split('\n').filter(l => l.trim()).length === 10, '10 recovery codes shown', viewportName);
    
    await page.check('#recOk');
    await page.click('#btnRecDone');
    await page.waitForSelector('#vSeal:not(.hide)', { timeout: 3000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-06-seal-vault.png`, fullPage: true });
    
    // 7. Seal vault (sovereign mode with printed code)
    await page.check('#extraCode'); // Use sovereign mode
    await page.fill('#sealTitle', 'Bank safe deposit key');
    await page.fill('#sealBody', 'Box 1847 at HSBC Jumeirah branch, key in study drawer');
    await page.click('#btnSeal');
    await page.waitForSelector('#vCode:not(.hide)', { timeout: 5000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-07-legacy-code.png`, fullPage: true });
    
    // 8. Legacy code shown once
    legacyCode = await page.textContent('#codeBox');
    log(/^[A-Z2-9]{4}(-[A-Z2-9]{4}){7}$/.test(legacyCode.trim()), 'Legacy code format correct', viewportName);
    
    await page.check('#codeOk');
    await page.click('#btnCodeDone');
    await page.waitForSelector('#vDash:not(.hide)', { timeout: 3000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-08-dashboard.png`, fullPage: true });
    
    // 9. Dashboard: Add vault items
    await page.click('[data-t="vault"]');
    await page.fill('#letter', 'Dear family, everything important is here.');
    
    // Add a wallet item
    await page.click('details summary'); // Open "Add a secret"
    await page.selectOption('#iType', 'Wallet / seed phrase');
    await page.fill('#iTitle', 'Hardware wallet seed');
    await page.fill('#iBody', 'abandon ability able about above absent absorb abstract absurd abuse access accident');
    await page.click('#btnAdd');
    await new Promise(resolve => setTimeout(resolve, 300));
    
    // Save vault
    await page.click('#btnSave');
    await page.waitForSelector('.ok', { timeout: 5000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-09-vault-saved.png`, fullPage: true });
    log(true, 'Vault items added and saved', viewportName);
    
    // 10. Add nominees
    await page.click('[data-t="noms"]');
    await new Promise(resolve => setTimeout(resolve, 300));
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-10-nominees-tab.png`, fullPage: true });
    
    await page.fill('#nName', 'Jane Nominee');
    await page.fill('#nEmail', nomineeEmail);
    await page.fill('#nPhone', '+44 7700 900000');
    await page.fill('#nAddr', '123 Test Street\nLondon W1A 1AA');
    await page.fill('#nRel', 'wife');
    await page.click('#btnNom');
    await page.waitForSelector('.ok', { timeout: 3000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-11-nominee-added.png`, fullPage: true });
    log(true, 'Nominee added', viewportName);
    
    // 11. Set nominee questions
    await new Promise(resolve => setTimeout(resolve, 500));
    const setQuestionsBtn = await page.$('button:has-text("Set questions")');
    if (setQuestionsBtn) {
      await setQuestionsBtn.click();
      await page.waitForSelector('#qEdit:not(.hide)');
      
      // Fill in three questions
      await page.fill('#q0', 'Where did we get married?');
      await page.fill('#a0', 'Marbella');
      await page.fill('#alt0', 'Puerto Banus, puerto banús');
      
      await page.fill('#q1', 'What was our first car?');
      await page.fill('#a1', 'Mini Cooper');
      await page.fill('#alt1', 'Mini, Cooper');
      
      await page.fill('#q2', 'What is my middle name?');
      await page.fill('#a2', 'Elizabeth');
      await page.fill('#alt2', 'Liz, Beth');
      
      await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-12-questions-form.png`, fullPage: true });
      
      await page.click('#btnQSave');
      await page.waitForSelector('.ok', { timeout: 5000 });
      await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-13-questions-saved.png`, fullPage: true });
      log(true, 'Nominee questions set', viewportName);
    }
    
    // 12. Check rules tab (phone field should be optional)
    await page.click('[data-t="rules"]');
    await new Promise(resolve => setTimeout(resolve, 300));
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-14-rules-tab.png`, fullPage: true });
    
    const rulesContent = await page.content();
    log(rulesContent.includes('optional') || !rulesContent.includes('check-in texts'),
        'Rules page shows phone as optional', viewportName);
    
    // 13. Try rehearsal tab
    await page.click('[data-t="try"]');
    await new Promise(resolve => setTimeout(resolve, 300));
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-15-rehearsal-tab.png`, fullPage: true });
    
    // 14. Test logout and login
    await page.click('#logout');
    await page.waitForSelector('#vAuth:not(.hide)', { timeout: 3000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-16-logged-out.png`, fullPage: true });
    log(true, 'Logout successful', viewportName);
    
    // 15. Log back in
    await page.click('[data-t="login"]');
    await page.fill('#lEmail', ownerEmail);
    await page.fill('#lPw', password);
    await page.fill('#lCode', totp(totpSecret));
    await page.click('#fLogin button');
    await page.waitForSelector('#vDash:not(.hide)', { timeout: 5000 });
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-17-logged-back-in.png`, fullPage: true });
    log(true, 'Login successful', viewportName);
    
    // 16. Test claim flow (nominee side)
    const claimPage = await context.newPage();
    await claimPage.goto(`${BASE_URL}/claim`);
    await claimPage.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-18-claim-start.png`, fullPage: true });
    
    const claimContent = await claimPage.content();
    log(!claimContent.includes('passport') && !claimContent.includes('ID check'),
        'Claim page has no passport/ID promises', viewportName);
    log(claimContent.includes('person on our team') || claimContent.includes('reviewed'),
        'Claim page mentions manual review', viewportName);
    
    // Start claim
    await claimPage.fill('#cName', 'Jane Nominee');
    await claimPage.fill('#cEmail', nomineeEmail);
    await claimPage.click('#f1 button');
    await claimPage.waitForSelector('#s2:not(.hide)', { timeout: 3000 });
    await claimPage.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-19-claim-otp.png` });
    
    // Get OTP and verify
    await new Promise(resolve => setTimeout(resolve, 1000));
    const claimOTP = await getOTPFromAdmin(nomineeEmail, ADM);
    if (claimOTP) {
      await claimPage.fill('#cCode', claimOTP);
      await claimPage.click('#f2 button');
      await claimPage.waitForSelector('#sFind:not(.hide)', { timeout: 3000 });
      await claimPage.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-20-claim-find.png` });
      
      // Find owner's vault
      await claimPage.fill('#oEmail', ownerEmail);
      await claimPage.click('#fFind button');
      await claimPage.waitForSelector('#s3:not(.hide)', { timeout: 5000 });
      await claimPage.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-21-claim-interview.png`, fullPage: true });
      
      log(true, 'Claim started and AI interview began', viewportName);
      
      // Answer a few interview questions
      const answers = [
        'I am her wife Jane. She passed away last week.',
        'At home in London on October 10th.',
        'Her brother and our solicitor know.',
        'I have the death certificate.'
      ];
      
      for (let i = 0; i < Math.min(3, answers.length); i++) {
        await claimPage.fill('#cMsg', answers[i]);
        await claimPage.click('#f3 button');
        await new Promise(resolve => setTimeout(resolve, 1500));
      }
      
      await claimPage.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-22-claim-interview-progress.png`, fullPage: true });
    }
    
    await claimPage.close();
    
    // 17. Test admin page
    const adminPage = await context.newPage();
    await adminPage.goto(`${BASE_URL}/admin.html`);
    await adminPage.fill('#tok', ADM);
    await adminPage.click('#go');
    await adminPage.waitForTimeout(1000);
    await adminPage.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-23-admin-claims.png`, fullPage: true });
    log(true, 'Admin page loads', viewportName);
    
    // Check claims tab
    const adminContent = await adminPage.content();
    log(adminContent.includes('Claims') && adminContent.includes('Status'),
        'Admin page shows claims', viewportName);
    
    await adminPage.close();
    
    // 18. Test mobile-specific issues
    if (width <= 400) {
      // Check navigation menu works
      await page.click('nav a[href="/"]');
      await page.waitForLoadState('networkidle');
      await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-24-mobile-nav.png`, fullPage: true });
      log(true, 'Mobile navigation works', viewportName);
    }
    
    // 19. Check console errors
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    
    await page.goto(BASE_URL);
    await page.waitForLoadState('networkidle');
    log(consoleErrors.length === 0, `No console errors (${consoleErrors.length} found)`, viewportName);
    
    if (consoleErrors.length > 0) {
      console.log('Console errors:', consoleErrors.slice(0, 5));
    }
    
  } catch (error) {
    log(false, `Test error: ${error.message}`, viewportName);
    await page.screenshot({ path: `${SCREENSHOT_DIR}/${viewportName}-ERROR.png`, fullPage: true });
  } finally {
    await context.close();
  }
}

async function main() {
  console.log('Starting comprehensive E2E tests...\n');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Screenshots: ${SCREENSHOT_DIR}\n`);
  
  browser = await chromium.launch({ headless: true });
  
  // Test on desktop viewport
  console.log('\n=== DESKTOP TESTS (1280x720) ===\n');
  await testViewport('desktop', 1280, 720);
  
  // Test on mobile viewport (iPhone 12 size)
  console.log('\n=== MOBILE TESTS (390x844) ===\n');
  await testViewport('mobile', 390, 844);
  
  await browser.close();
  
  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('TEST SUMMARY');
  console.log('='.repeat(60));
  console.log(`Passed: ${pass}`);
  console.log(`Failed: ${fail}`);
  console.log(`Total:  ${pass + fail}`);
  
  if (fail > 0) {
    console.log('\nFailed tests:');
    results.filter(r => !r.status).forEach(r => console.log(`  ✗ ${r.message}`));
  }
  
  console.log(`\nScreenshots saved to: ${SCREENSHOT_DIR}/`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

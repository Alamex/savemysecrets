// Save My Secrets — alpha Worker (API + daily check-in cron)
// The server never sees the master password or the legacy code. NOTE: in standard mode (the alpha default)
// it stores the release share that can unwrap the vault key, so it could open vaults. See README.

const BRAND = 'Save My Secrets';
const DAY = 86400000;
const enc = new TextEncoder();

// ---------- helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });
const err = (msg, status = 400) => json({ error: msg }, status);
const now = () => Date.now();
const rid = (n = 16) => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, '0')).join('');
const b64 = buf => { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function sha256hex(s) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function pbkdf2(secret, saltB64, iters = 100000) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iters }, key, 256);
  return b64(bits);
}
function safeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------- TOTP (RFC 6238) ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(bytes) {
  let bits = 0, val = 0, out = '';
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function b32decode(s) {
  s = s.replace(/=+$/, '').toUpperCase(); let bits = 0, val = 0; const out = [];
  for (const c of s) { val = (val << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
async function totpAt(secret, counter) {
  const key = await crypto.subtle.importKey('raw', b32decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new ArrayBuffer(8); new DataView(msg).setUint32(4, counter);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = h[19] & 15;
  const code = ((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6;
  return String(code).padStart(6, '0');
}
async function totpVerify(secret, code) {
  const c = Math.floor(now() / 30000);
  for (const d of [-1, 0, 1]) if (await totpAt(secret, c + d) === String(code).trim()) return true;
  return false;
}

// ---------- messaging (email / SMS / WhatsApp) ----------
// Alpha: real send if keys are configured, otherwise logged to the events table (visible in admin).
async function logEvent(env, userId, kind, detail) {
  await env.DB.prepare('INSERT INTO events (user_id, kind, detail, at) VALUES (?,?,?,?)')
    .bind(userId, kind, typeof detail === 'string' ? detail : JSON.stringify(detail), now()).run();
}
async function sendEmail(env, userId, to, subject, html) {
  if (env.RESEND_API_KEY) {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: env.MAIL_FROM || `${BRAND} <alerts@savemysecrets.com>`, to, subject, html }),
    });
    await logEvent(env, userId, 'email', { to, subject, ok: r.ok });
  } else await logEvent(env, userId, 'email(dry-run)', { to, subject, html });
}
async function sendText(env, userId, to, body, channel = 'sms') {
  if (!to) return;
  if (env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM) {
    const from = channel === 'whatsapp' ? `whatsapp:${env.TWILIO_WA_FROM || env.TWILIO_FROM}` : env.TWILIO_FROM;
    const dest = channel === 'whatsapp' ? `whatsapp:${to}` : to;
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, {
      method: 'POST',
      headers: { authorization: 'Basic ' + btoa(`${env.TWILIO_SID}:${env.TWILIO_TOKEN}`), 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ From: from, To: dest, Body: body }),
    });
    await logEvent(env, userId, channel, { to, ok: r.ok });
  } else await logEvent(env, userId, `${channel}(dry-run)`, { to, body });
}

// ---------- invites ----------
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 32);
async function validInvite(env, c) {
  return env.DB.prepare('SELECT code FROM invites WHERE code=? AND active=1 AND uses<max_uses AND (expires_at IS NULL OR expires_at>?)').bind(normCode(c), now()).first();
}

// ---------- sessions ----------
async function makeSession(env, userId, stage, hours = 12) {
  const token = rid(32);
  await env.DB.prepare('INSERT INTO sessions (token, user_id, stage, expires_at) VALUES (?,?,?,?)')
    .bind(token, userId, stage, now() + hours * 3600000).run();
  return token;
}
async function auth(req, env, stage = 'full') {
  const t = (req.headers.get('authorization') || '').replace('Bearer ', '');
  if (!t) return null;
  const s = await env.DB.prepare('SELECT * FROM sessions WHERE token=? AND expires_at>?').bind(t, now()).first();
  if (!s || (stage === 'full' && s.stage !== 'full')) return null;
  return env.DB.prepare('SELECT * FROM users WHERE id=?').bind(s.user_id).first();
}

// Signed check-in link, so the owner can confirm from email without logging in
async function checkinSig(env, userId, issued) {
  return (await sha256hex(`${env.APP_SECRET || 'dev-secret'}|checkin|${userId}|${issued}`)).slice(0, 32);
}
function baseUrl(req, env) { return env.BASE_URL || new URL(req.url).origin; }

async function resetCheckin(env, u, how) {
  await env.DB.prepare(`UPDATE users SET state='active', next_checkin_at=?, overdue_since=NULL, last_reminder_at=NULL,
    reminders_sent=0, veto_ends_at=NULL WHERE id=?`).bind(now() + u.checkin_days * DAY, u.id).run();
  // An owner proving they're alive cancels any open claim
  await env.DB.prepare(`UPDATE claims SET status='vetoed', updated_at=? WHERE user_id=? AND status NOT IN ('released','rejected','vetoed')`)
    .bind(now(), u.id).run();
  await logEvent(env, u.id, 'checkin', how);
}

// ---------- the escalation state machine (runs daily from cron, also callable by admin) ----------
export async function runEscalation(env, origin, at = now()) {
  const { results: users } = await env.DB.prepare(`SELECT * FROM users WHERE state IN ('active','overdue','veto_window') AND wrapped_release IS NOT NULL`).all();
  const out = [];
  for (const u of users) {
    const issued = at;
    const link = `${origin}/api/checkin?u=${u.id}&i=${issued}&s=${await checkinSig(env, u.id, issued)}`;
    const btn = `<p><a href="${link}" style="background:#111;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none">Yes, I'm fine</a></p>`;

    if (u.state === 'active' && at >= u.next_checkin_at) {
      await sendEmail(env, u.id, u.email, `${BRAND}: quick check-in`, `<p>Hi ${u.name},</p><p>Your regular check-in. One tap and we'll see you next time.</p>${btn}`);
      await env.DB.prepare(`UPDATE users SET state='overdue', overdue_since=?, last_reminder_at=?, reminders_sent=1 WHERE id=?`).bind(at, at, u.id).run();
      out.push([u.email, 'first reminder']);
    } else if (u.state === 'overdue' && at - u.last_reminder_at >= 7 * DAY) {
      const weeks = Math.floor((at - u.overdue_since) / (7 * DAY));
      if (weeks >= u.grace_weeks) {
        const { results: noms } = await env.DB.prepare('SELECT * FROM nominees WHERE user_id=?').bind(u.id).all();
        for (const n of noms) {
          await sendEmail(env, u.id, n.email, `Is ${u.name} OK?`,
            `<p>Hi ${n.name},</p><p>${u.name} named you as a trusted contact on ${BRAND} and hasn't responded to our check-ins for ${weeks} weeks.</p>
             <p>Could you let us know they're OK? If something has happened, you can start the process here:</p>
             <p><a href="${origin}/claim?u=${u.id}">${origin}/claim</a></p>`);
          await sendText(env, u.id, n.phone, `${BRAND}: ${u.name} has not responded to check-ins. Please see your email from us.`, 'sms');
        }
        await env.DB.prepare(`UPDATE users SET state='nominees_contacted', last_reminder_at=? WHERE id=?`).bind(at, u.id).run();
        out.push([u.email, `nominees contacted (${noms.length})`]);
      } else {
        await sendEmail(env, u.id, u.email, `${BRAND}: we haven't heard from you (week ${weeks + 1})`, `<p>Hi ${u.name}, please confirm you're OK.</p>${btn}`);
        await sendText(env, u.id, u.phone, `${BRAND}: please confirm you're OK: ${link}`, weeks % 2 ? 'whatsapp' : 'sms');
        await env.DB.prepare(`UPDATE users SET last_reminder_at=?, reminders_sent=reminders_sent+1 WHERE id=?`).bind(at, u.id).run();
        out.push([u.email, `follow-up week ${weeks + 1}`]);
      }
    } else if (u.state === 'veto_window') {
      if (at >= u.veto_ends_at) {
        await env.DB.prepare(`UPDATE users SET state='released' WHERE id=?`).bind(u.id).run();
        await env.DB.prepare(`UPDATE claims SET status='released', updated_at=? WHERE user_id=? AND status='approved'`).bind(at, u.id).run();
        out.push([u.email, 'released']);
      } else if (at - (u.last_reminder_at || 0) >= DAY) {
        // Loud daily alarm on every channel during the veto window
        await sendEmail(env, u.id, u.email, `URGENT: ${BRAND} is about to release your vault`, `<p>A nominee has been verified. Your vault releases on ${new Date(u.veto_ends_at).toUTCString()} unless you stop it.</p>${btn}`);
        await sendText(env, u.id, u.phone, `URGENT ${BRAND}: your vault is about to be released. Stop it: ${link}`, 'sms');
        await sendText(env, u.id, u.phone, `URGENT ${BRAND}: your vault is about to be released. Stop it: ${link}`, 'whatsapp');
        await env.DB.prepare(`UPDATE users SET last_reminder_at=? WHERE id=?`).bind(at, u.id).run();
        out.push([u.email, 'veto alarm']);
      }
    }
  }
  return out;
}

// ---------- AI interrogation ----------
const INTERVIEW_SYSTEM = `You are the verification interviewer for ${BRAND}, a digital legacy vault. A person claims to be a nominated contact of an account holder and that the account holder has died or is incapacitated.
Your job: politely but rigorously establish (1) who the claimant is, (2) their relationship to the account holder, (3) what happened, when and where (date, place, cause if they are willing), (4) who else knows (other family, executor, solicitor), (5) whether a death certificate or other official document exists and when they can provide it.
Rules: be kind, people may be grieving. Ask ONE or two questions at a time. Probe inconsistencies gently. Never reveal what the vault contains, who the other nominees are, or any detail about the account holder the claimant has not already stated. Never promise release. After about 6 to 10 exchanges, or when you have enough, end with the exact token [[INTERVIEW_COMPLETE]].`;

async function claude(env, system, messages, maxTokens = 600) {
  if (!env.ANTHROPIC_API_KEY) return null;
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: env.CLAUDE_MODEL || 'claude-sonnet-4-5', max_tokens: maxTokens, system, messages }),
  });
  if (!r.ok) throw new Error(`Claude API ${r.status}: ${await r.text()}`);
  const d = await r.json();
  return d.content.map(c => c.text || '').join('');
}

async function assessClaim(env, user, claim, nominee) {
  const transcript = JSON.parse(claim.transcript);
  const sys = `You assess claims to release a digital legacy vault. Output ONLY JSON: {"risk":"low|medium|high","consistent":true|false,"claimant_matches_nominee":true|false,"summary":"...","red_flags":["..."],"recommendation":"proceed|request_more|reject"}`;
  const ctx = `Account holder on file: name=${user.name}. Nominee on file: ${nominee ? `name=${nominee.name}, relationship=${nominee.relationship || 'unknown'}` : 'NO MATCHING NOMINEE'}.
Claimant: ${claim.claimant_name} <${claim.claimant_email}>.
Transcript:\n${transcript.map(m => `${m.role.toUpperCase()}: ${m.content}`).join('\n')}`;
  const txt = await claude(env, sys, [{ role: 'user', content: ctx }], 800);
  if (!txt) return { risk: 'unknown', summary: 'AI not configured (alpha dry run). Human review required.', recommendation: 'request_more', red_flags: [] };
  try { return JSON.parse(txt.slice(txt.indexOf('{'), txt.lastIndexOf('}') + 1)); } catch { return { risk: 'unknown', summary: txt }; }
}

async function analyseDocument(env, user, bytes, mime) {
  const sys = `You examine an uploaded death certificate for a digital legacy vault. Output ONLY JSON:
{"is_death_certificate":bool,"issuing_country":"","issuing_authority":"","deceased_name":"","date_of_death":"","registration_number":"","name_matches_account":bool,"tampering_signs":["..."],"verification_route":"how a human can independently verify this with the issuing registry","confidence":"low|medium|high"}`;
  if (!env.ANTHROPIC_API_KEY) return { note: 'AI not configured (alpha dry run). Manual review required.' };
  const isPdf = mime === 'application/pdf';
  const block = isPdf
    ? { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: b64(bytes) } }
    : { type: 'image', source: { type: 'base64', media_type: mime, data: b64(bytes) } };
  const txt = await claude(env, sys, [{ role: 'user', content: [block, { type: 'text', text: `Account holder name on file: ${user.name}` }] }], 800);
  try { return JSON.parse(txt.slice(txt.indexOf('{'), txt.lastIndexOf('}') + 1)); } catch { return { raw: txt }; }
}

function isAdmin(req, env) {
  const t = (req.headers.get('authorization') || '').replace('Bearer ', '');
  return env.ADMIN_TOKEN && safeEq(t, env.ADMIN_TOKEN);
}

// ---------- router ----------
async function api(req, env) {
  const url = new URL(req.url);
  const p = url.pathname;
  const m = req.method;
  const body = m === 'POST' && (req.headers.get('content-type') || '').includes('json') ? await req.json().catch(() => ({})) : {};

  // Waitlist (conference)
  if ((p === '/api/waitlist' || p === '/api/subscribe') && m === 'GET') return json({ ok: true, service: 'savemysecrets-signups' });
  if ((p === '/api/waitlist' || p === '/api/subscribe') && m === 'POST') {
    const email = String(body.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ ok: false, error: 'Please enter a valid email address' }, 400);
    await env.DB.prepare('INSERT OR IGNORE INTO signups (email, source, ip, ua) VALUES (?,?,?,?)')
      .bind(email, String(body.source || 'site').slice(0, 40), req.headers.get('cf-connecting-ip') || '', (req.headers.get('user-agent') || '').slice(0, 300)).run();
    return json({ ok: true });
  }

  // Preview only: AI judges whether a nominee's answer means the same as the owner's answer
  if (p === '/api/preview/judge' && m === 'POST') {
    const clip = v => String(v || '').slice(0, 200);
    const q = clip(body.question), exp = clip(body.expected), given = clip(body.given);
    const alts = (Array.isArray(body.alternatives) ? body.alternatives : []).slice(0, 10).map(clip);
    if (!q || !exp || !given) return err('Missing fields');
    const sys = `You check answers to a security question for a digital legacy vault. The owner set the question and answer; a person claiming to be their nominee has answered.
Decide: "match" if it is the same answer (spelling, accents, capitals, word order aside); "close" if it clearly refers to the same specific thing in a different way (a district inside the same town, a nickname, a translation, a well-known alternative name, a misspelling); "no" otherwise. Be strict: a broader answer (a country for a town), a guess, a different place, or a vague answer is "no".
Reply ONLY with JSON: {"verdict":"match|close|no","reason":"under 12 words, never state or hint at the owner's answer"}`;
    const txt = await claude(env, sys, [{ role: 'user', content: `Question: ${q}\nOwner's answer: ${exp}\nOwner's accepted alternatives: ${alts.join('; ') || 'none'}\nNominee's answer: ${given}` }], 120);
    if (!txt) return json({ verdict: 'no', reason: 'AI not configured' });
    try { const d = JSON.parse(txt.slice(txt.indexOf('{'), txt.lastIndexOf('}') + 1)); return json({ verdict: ['match', 'close', 'no'].includes(d.verdict) ? d.verdict : 'no', reason: String(d.reason || '').slice(0, 120) }); }
    catch { return json({ verdict: 'no', reason: '' }); }
  }

  // Invite codes: sign-up is invite-only during the alpha
  if (p === '/api/invite/check' && m === 'POST') {
    const inv = await validInvite(env, body.code);
    return inv ? json({ ok: true }) : json({ ok: false, error: 'That invite code isn\'t valid or has been used up.' }, 400);
  }

  // Step 1 of signup: get a fresh KDF salt so the client can derive keys before registering
  if (p === '/api/register' && m === 'POST') {
    const { email, name, phone, authKey, kdfSalt } = body;
    if (!email || !name || !authKey || !kdfSalt) return err('Missing fields');
    const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email.toLowerCase()).first();
    if (exists) return err('An account with that email already exists');
    const code = normCode(body.inviteCode);
    // Atomic: only succeeds if the code is valid and still has uses left
    const used = await env.DB.prepare(`UPDATE invites SET uses=uses+1 WHERE code=? AND active=1 AND uses<max_uses AND (expires_at IS NULL OR expires_at>?)`).bind(code, now()).run();
    if (!used.meta.changes) return err('That invite code isn\'t valid or has been used up.', 403);
    const id = rid(12), authSalt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    await env.DB.prepare(`INSERT INTO users (id,email,name,phone,auth_salt,auth_hash,kdf_salt,totp_secret,invite_code,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .bind(id, email.toLowerCase(), name, phone || null, authSalt, await pbkdf2(authKey, authSalt), kdfSalt, secret, code, now()).run();
    const token = await makeSession(env, id, 'enrol', 1);
    const otpauth = `otpauth://totp/${encodeURIComponent(BRAND)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(BRAND)}`;
    return json({ token, totpSecret: secret, otpauth });
  }

  if (p === '/api/2fa/enable' && m === 'POST') {
    const t = (req.headers.get('authorization') || '').replace('Bearer ', '');
    const s = await env.DB.prepare(`SELECT * FROM sessions WHERE token=? AND stage='enrol' AND expires_at>?`).bind(t, now()).first();
    if (!s) return err('Session expired', 401);
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(s.user_id).first();
    if (!(await totpVerify(u.totp_secret, body.code))) return err('That code did not match. Check your authenticator app clock.');
    await env.DB.prepare('UPDATE users SET totp_enabled=1 WHERE id=?').bind(u.id).run();
    await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(t).run();
    return json({ token: await makeSession(env, u.id, 'full'), kdfSalt: u.kdf_salt });
  }

  if (p === '/api/prelogin' && m === 'POST') {
    const u = await env.DB.prepare('SELECT kdf_salt FROM users WHERE email=?').bind(String(body.email || '').toLowerCase()).first();
    // Deterministic fake salt for unknown emails so we don't leak who has an account
    return json({ kdfSalt: u ? u.kdf_salt : b64(unb64(btoa((await sha256hex('salt|' + body.email)).slice(0, 16)))) });
  }

  if (p === '/api/login' && m === 'POST') {
    const u = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(String(body.email || '').toLowerCase()).first();
    if (!u || !safeEq(await pbkdf2(body.authKey || '', u.auth_salt), u.auth_hash)) return err('Email or password incorrect', 401);
    if (!u.totp_enabled) return json({ token: await makeSession(env, u.id, 'enrol', 1), needsEnrol: true, totpSecret: u.totp_secret });
    if (!(await totpVerify(u.totp_secret, body.code))) return err('Two-factor code incorrect', 401);
    await resetCheckin(env, { ...u, checkin_days: u.checkin_days }, 'login');   // logging in counts as proof of life
    return json({ token: await makeSession(env, u.id, 'full') });
  }

  if (p === '/api/checkin' && m === 'GET') {
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(url.searchParams.get('u')).first();
    const ok = u && safeEq(url.searchParams.get('s') || '', await checkinSig(env, u.id, url.searchParams.get('i')))
      && now() - Number(url.searchParams.get('i')) < 120 * DAY;
    if (!ok) return new Response('This link is invalid or has expired. Please log in instead.', { status: 400 });
    if (u.state === 'released') return new Response('This vault has already been released.', { status: 409 });
    await resetCheckin(env, u, 'email link');
    return new Response(null, { status: 302, headers: { location: `${baseUrl(req, env)}/app?checkedin=1` } });
  }

  // ---- owner (logged in, 2FA done) ----
  if (p.startsWith('/api/me')) {
    const u = await auth(req, env);
    if (!u) return err('Please log in', 401);

    if (p === '/api/me' && m === 'GET') {
      const { results: nominees } = await env.DB.prepare('SELECT * FROM nominees WHERE user_id=? ORDER BY created_at').bind(u.id).all();
      return json({
        name: u.name, email: u.email, phone: u.phone, kdfSalt: u.kdf_salt,
        vault: u.vault_ct, wrappedOwner: u.wrapped_owner, hasRelease: !!u.wrapped_release, releaseMode: u.release_mode,
        policy: { checkin_days: u.checkin_days, grace_weeks: u.grace_weeks, proof_required: u.proof_required, veto_days: u.veto_days },
        state: u.state, nextCheckin: u.next_checkin_at, nominees,
      });
    }
    if (p === '/api/me/vault' && m === 'POST') {
      // Client sends ciphertext only. serverShare + wrappedRelease are set when the vault is first sealed or re-keyed.
      const { vault, wrappedOwner, wrappedRelease, serverShare, releaseMode } = body;
      if (!vault || !wrappedOwner) return err('Missing vault');
      if (wrappedRelease && serverShare) {
        await env.DB.prepare('UPDATE users SET vault_ct=?, wrapped_owner=?, wrapped_release=?, server_share=?, release_mode=? WHERE id=?')
          .bind(vault, wrappedOwner, wrappedRelease, serverShare, releaseMode === 'standard' ? 'standard' : 'sovereign', u.id).run();
        if (!u.next_checkin_at) await resetCheckin(env, u, 'vault sealed');
      } else {
        await env.DB.prepare('UPDATE users SET vault_ct=?, wrapped_owner=? WHERE id=?').bind(vault, wrappedOwner, u.id).run();
      }
      await logEvent(env, u.id, 'vault_saved', '');
      return json({ ok: true });
    }
    if (p === '/api/me/policy' && m === 'POST') {
      const cd = Math.max(30, Math.min(365, Number(body.checkin_days) || 90));
      const gw = Math.max(2, Math.min(12, Number(body.grace_weeks) || 6));
      const pr = ['none', 'nominee_confirm', 'death_certificate'].includes(body.proof_required) ? body.proof_required : 'death_certificate';
      const vd = Math.max(3, Math.min(30, Number(body.veto_days) || 7));
      await env.DB.prepare('UPDATE users SET checkin_days=?, grace_weeks=?, proof_required=?, veto_days=?, phone=COALESCE(?,phone) WHERE id=?')
        .bind(cd, gw, pr, vd, body.phone || null, u.id).run();
      return json({ ok: true });
    }
    if (p === '/api/me/nominees' && m === 'POST') {
      const { name, email, phone, address, relationship, notify_early } = body;
      if (!name || !email) return err('Nominee needs at least a name and email');
      const id = rid(10);
      await env.DB.prepare('INSERT INTO nominees (id,user_id,name,email,phone,address,relationship,notify_early,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(id, u.id, name, email.toLowerCase(), phone || null, address || null, relationship || null, notify_early ? 1 : 0, now()).run();
      if (notify_early) await sendEmail(env, u.id, email, `${u.name} has named you as a trusted contact`,
        `<p>Hi ${name},</p><p>${u.name} has named you as a trusted contact on ${BRAND}. You don't need to do anything now. If ${u.name} ever stops responding to our check-ins, we'll be in touch.</p>`);
      return json({ ok: true, id });
    }
    if (p.startsWith('/api/me/nominees/') && m === 'DELETE') {
      await env.DB.prepare('DELETE FROM nominees WHERE id=? AND user_id=?').bind(p.split('/').pop(), u.id).run();
      return json({ ok: true });
    }
    if (p === '/api/me/checkin' && m === 'POST') { await resetCheckin(env, u, 'in app'); return json({ ok: true }); }
  }

  // ---- nominee claim flow ----
  if (p === '/api/claim/start' && m === 'POST') {
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(body.u).first();
    // Same response whether or not anything matches, so the claim page can't be used to probe accounts
    const generic = json({ ok: true, message: 'If your details match our records you will receive a code by email.' });
    if (!u) return generic;
    const email = String(body.email || '').toLowerCase();
    const nominee = await env.DB.prepare('SELECT * FROM nominees WHERE user_id=? AND email=?').bind(u.id, email).first();
    const otp = String(Math.floor(100000 + Math.random() * 900000)), id = rid(12);
    // Non-nominees can still start a claim (e.g. an executor) but they are flagged for the AI and the reviewer
    await env.DB.prepare('INSERT INTO claims (id,user_id,nominee_id,claimant_email,claimant_name,otp_hash,otp_expires,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(id, u.id, nominee ? nominee.id : null, email, String(body.name || '').slice(0, 120), await sha256hex(otp + id), now() + 20 * 60000, now(), now()).run();
    await sendEmail(env, u.id, email, `${BRAND} verification code`, `<p>Your code is <b>${otp}</b>. It expires in 20 minutes.</p>`);
    await logEvent(env, u.id, 'claim_started', { claim: id, email, nominee: !!nominee });
    return json({ ok: true, claimId: id, message: 'If your details match our records you will receive a code by email.' });
  }
  if (p === '/api/claim/verify' && m === 'POST') {
    const c = await env.DB.prepare('SELECT * FROM claims WHERE id=?').bind(body.claimId).first();
    if (!c || c.status !== 'otp' || now() > c.otp_expires || !safeEq(await sha256hex(String(body.code) + c.id), c.otp_hash)) return err('Code incorrect or expired', 401);
    const token = rid(32);
    const u = await env.DB.prepare('SELECT name FROM users WHERE id=?').bind(c.user_id).first();
    const first = `Thank you, ${c.claimant_name || 'and welcome'}. I'm sorry you're dealing with this. I'll ask a few questions so we can handle this properly and protect ${u.name}'s wishes. To start: what is your relationship to ${u.name}, and what has happened?`;
    await env.DB.prepare(`UPDATE claims SET status='interview', token=?, transcript=?, updated_at=? WHERE id=?`)
      .bind(token, JSON.stringify([{ role: 'assistant', content: first }]), now(), c.id).run();
    return json({ token, message: first });
  }
  if (p.startsWith('/api/claim/') && p !== '/api/claim/start' && p !== '/api/claim/verify') {
    const t = (req.headers.get('authorization') || '').replace('Bearer ', '');
    const c = t && await env.DB.prepare('SELECT * FROM claims WHERE token=?').bind(t).first();
    if (!c) return err('Claim session not found', 401);
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(c.user_id).first();
    const nominee = c.nominee_id ? await env.DB.prepare('SELECT * FROM nominees WHERE id=?').bind(c.nominee_id).first() : null;

    if (p === '/api/claim/message' && m === 'POST') {
      if (c.status !== 'interview') return err('Interview already finished');
      const tr = JSON.parse(c.transcript);
      tr.push({ role: 'user', content: String(body.text || '').slice(0, 2000) });
      const sys = INTERVIEW_SYSTEM + `\nAccount holder first name: ${u.name.split(' ')[0]}. Claimant is ${nominee ? 'a listed nominee' : 'NOT a listed nominee; establish their standing (executor? solicitor? family?) carefully'}.`;
      let reply = await claude(env, sys, tr.map(x => ({ role: x.role, content: x.content })));
      if (reply === null) reply = tr.filter(x => x.role === 'user').length >= 3 ? 'Thank you. That is everything I need for now. [[INTERVIEW_COMPLETE]]'
        : ['When and where did this happen?', 'Who else in the family, or which solicitor or executor, is involved?', 'Is a death certificate available, and when could you upload it?'][tr.filter(x => x.role === 'user').length - 1];
      const done = reply.includes('[[INTERVIEW_COMPLETE]]');
      reply = reply.replace('[[INTERVIEW_COMPLETE]]', '').trim();
      tr.push({ role: 'assistant', content: reply });
      let status = 'interview';
      if (done) status = u.proof_required === 'death_certificate' ? 'awaiting_document' : 'review';
      await env.DB.prepare('UPDATE claims SET transcript=?, status=?, updated_at=? WHERE id=?').bind(JSON.stringify(tr), status, now(), c.id).run();
      if (done) {
        const a = await assessClaim(env, u, { ...c, transcript: JSON.stringify(tr) }, nominee);
        await env.DB.prepare('UPDATE claims SET ai_assessment=? WHERE id=?').bind(JSON.stringify(a), c.id).run();
        if (status === 'review') await env.DB.prepare(`UPDATE users SET state='claim_review' WHERE id=?`).bind(u.id).run();
      }
      return json({ reply, done, status });
    }
    if (p === '/api/claim/document' && m === 'POST') {
      if (c.status !== 'awaiting_document') return err('No document needed at this stage');
      const form = await req.formData(); const f = form.get('file');
      if (!f || f.size > 1.8 * 1024 * 1024) return err('Please upload a PDF or photo under 2 MB');
      const mime = f.type || 'application/octet-stream';
      if (!['application/pdf', 'image/jpeg', 'image/png', 'image/webp'].includes(mime)) return err('PDF, JPG, PNG or WEBP only');
      const bytes = new Uint8Array(await f.arrayBuffer()); const key = `claims/${c.id}/${rid(6)}-${f.name}`.replace(/[^\w./-]/g, '_');
      if (env.DOCS) await env.DOCS.put(key, bytes, { httpMetadata: { contentType: mime } });
      else await env.DB.prepare('INSERT INTO docs (key, mime, data, created_at) VALUES (?,?,?,?)').bind(key, mime, b64(bytes), now()).run();
      const analysis = await analyseDocument(env, u, bytes, mime);
      await env.DB.prepare(`UPDATE claims SET doc_key=?, doc_analysis=?, status='review', updated_at=? WHERE id=?`).bind(key, JSON.stringify(analysis), now(), c.id).run();
      await env.DB.prepare(`UPDATE users SET state='claim_review' WHERE id=?`).bind(u.id).run();
      return json({ ok: true, status: 'review' });
    }
    if (p === '/api/claim/status' && m === 'GET') {
      const out = { status: c.status, proofRequired: u.proof_required };
      if (c.status === 'released') {
        // Release package: server share + ciphertext. The nominee still needs the legacy code (sovereign mode).
        out.package = { name: u.name, vault: u.vault_ct, wrappedRelease: u.wrapped_release, serverShare: u.server_share, releaseMode: u.release_mode };
      } else if (c.status === 'approved') out.vetoEndsAt = u.veto_ends_at;
      return json(out);
    }
  }

  // ---- admin review ----
  if (p.startsWith('/api/admin')) {
    if (!isAdmin(req, env)) return err('Not authorised', 401);
    if (p === '/api/admin/claims' && m === 'GET') {
      const { results } = await env.DB.prepare(`SELECT c.*, u.name AS owner_name, u.email AS owner_email, u.proof_required, u.state AS owner_state,
        n.name AS nominee_name, n.relationship FROM claims c JOIN users u ON u.id=c.user_id LEFT JOIN nominees n ON n.id=c.nominee_id
        ORDER BY c.updated_at DESC LIMIT 100`).all();
      return json(results);
    }
    if (p === '/api/admin/decide' && m === 'POST') {
      const c = await env.DB.prepare('SELECT * FROM claims WHERE id=?').bind(body.claimId).first();
      if (!c || c.status !== 'review') return err('Claim not awaiting review');
      const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(c.user_id).first();
      if (body.decision === 'approve') {
        const ends = now() + u.veto_days * DAY;
        await env.DB.prepare(`UPDATE claims SET status='approved', admin_note=?, updated_at=? WHERE id=?`).bind(body.note || '', now(), c.id).run();
        await env.DB.prepare(`UPDATE users SET state='veto_window', veto_ends_at=?, last_reminder_at=0 WHERE id=?`).bind(ends, u.id).run();
      } else {
        await env.DB.prepare(`UPDATE claims SET status='rejected', admin_note=?, updated_at=? WHERE id=?`).bind(body.note || '', now(), c.id).run();
        await env.DB.prepare(`UPDATE users SET state='nominees_contacted' WHERE id=?`).bind(u.id).run();
      }
      await logEvent(env, u.id, 'admin_decision', { claim: c.id, decision: body.decision });
      return json({ ok: true });
    }
    if (p === '/api/admin/doc' && m === 'GET') {
      const key = url.searchParams.get('key');
      const o = env.DOCS && await env.DOCS.get(key);
      if (o) return new Response(o.body, { headers: { 'content-type': o.httpMetadata?.contentType || 'application/octet-stream' } });
      const d = await env.DB.prepare('SELECT mime, data FROM docs WHERE key=?').bind(key).first();
      return d ? new Response(unb64(d.data), { headers: { 'content-type': d.mime } }) : err('Not found', 404);
    }
    if (p === '/api/admin/run-escalation' && m === 'POST') {
      // Test hook: simulate the cron at a future time
      return json(await runEscalation(env, baseUrl(req, env), body.at || now()));
    }
    if (p === '/api/admin/events' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM events ORDER BY id DESC LIMIT 200').all();
      return json(results);
    }
    if (p === '/api/admin/waitlist' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT email, source, created_at FROM signups ORDER BY id DESC').all();
      return json(results);
    }
    if (p === '/api/admin/invites' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM invites ORDER BY created_at DESC').all();
      return json(results);
    }
    if (p === '/api/admin/invites' && m === 'POST') {
      const code = normCode(body.code) || [...crypto.getRandomValues(new Uint8Array(6))].map(b => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 32]).join('');
      if (code.length < 4) return err('Code must be at least 4 characters');
      const max = Math.max(1, Math.min(100000, Number(body.max_uses) || 100));
      const exp = body.expires_days ? now() + Number(body.expires_days) * DAY : null;
      await env.DB.prepare('INSERT INTO invites (code, label, max_uses, uses, active, expires_at, created_at) VALUES (?,?,?,0,1,?,?) ON CONFLICT(code) DO UPDATE SET label=excluded.label, max_uses=excluded.max_uses, active=1, expires_at=excluded.expires_at')
        .bind(code, String(body.label || '').slice(0, 80), max, exp, now()).run();
      return json({ ok: true, code });
    }
    if (p === '/api/admin/invites/toggle' && m === 'POST') {
      await env.DB.prepare('UPDATE invites SET active=1-active WHERE code=?').bind(normCode(body.code)).run();
      return json({ ok: true });
    }
  }
  return err('Not found', 404);
}

export async function handleRequest(req, env) {
  const url = new URL(req.url);
  if (url.pathname.startsWith('/api/')) {
    try { const res = await api(req, env); res.headers.set('cache-control', 'no-store'); return res; }
    catch (e) { return err(`Server error: ${e.message}`, 500); }
  }
  const res = await env.ASSETS.fetch(req);
  // No dead URLs: anything that doesn't exist goes to the homepage
  if (res.status === 404) return new Response(null, { status: 301, headers: { location: url.origin + '/' } });
  return res;
}

export default {
  fetch: (req, env) => handleRequest(req, env),
  async scheduled(event, env) {
    await runEscalation(env, env.BASE_URL || 'https://savemysecrets.com');
  },
};

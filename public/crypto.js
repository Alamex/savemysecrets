// Save My Secrets: client-side crypto. Everything sensitive is encrypted in the browser.
// Keys:
//   password --PBKDF2(600k)--> authKey (sent to server, hashed again there) + ownerKey (never leaves browser)
//   K  = random vault key; vault JSON is AES-256-GCM encrypted with K
//   wrappedOwner   = AES-GCM(ownerKey, K)
//   S  = server share (held by the service, released only after verification)
//   L  = legacy code (printed, given to the nominee; never sent to the service in sovereign mode)
//   wrappedRelease = AES-GCM(SHA-256(S || L), K)
// Sovereign mode (printed legacy code): neither the service (S) nor the nominee (L) can open a vault alone.
// Standard mode (the alpha default): L is all zeros, so the service's share S alone CAN open the vault.
// Nominee questions mode: each nominee has three questions. For every pair of answers (any two of three),
// L = SHA-256(h_i || h_j) with h = PBKDF2(normalised answer, salt, 200k). A copy of K is wrapped with SHA-256(S || L)
// for each pair (and each owner-listed alternative). The service never sees the answers, so it cannot open these copies;
// it only stores verifiers so it can release S after the nominee proves two correct answers, with escalating waits.

function SMSFactory() {
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = u8 => btoa(String.fromCharCode(...new Uint8Array(u8)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const rand = n => crypto.getRandomValues(new Uint8Array(n));
  const B32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I, O, 0, 1 to avoid misreading on paper

  function codeEncode(bytes) { // 20 bytes -> 32 chars, groups of 4
    let bits = 0, val = 0, out = '';
    for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits) out += B32[(val << (5 - bits)) & 31];
    return out.match(/.{1,4}/g).join('-');
  }
  function codeDecode(s) {
    s = s.toUpperCase().replace(/[^A-Z0-9]/g, '');
    let bits = 0, val = 0; const out = [];
    for (const c of s) { const i = B32.indexOf(c); if (i < 0) throw new Error('Invalid character in code'); val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
    if (out.length !== 20) throw new Error('Legacy code should be 32 characters');
    return new Uint8Array(out);
  }

  async function deriveFromPassword(password, kdfSaltB64) {
    const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(kdfSaltB64), iterations: 600000 }, base, 512));
    return { authKey: b64(bits.slice(0, 32)), ownerKey: bits.slice(32) };
  }
  async function aesKey(raw) { return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); }
  async function seal(raw, data) {
    const iv = rand(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(raw), data));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return b64(out);
  }
  async function open(raw, b) {
    const u = unb64(b);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, await aesKey(raw), u.slice(12)));
  }
  async function releaseKey(S, L) {
    const m = new Uint8Array(S.length + L.length); m.set(S); m.set(L, S.length);
    return new Uint8Array(await crypto.subtle.digest('SHA-256', m));
  }
  const encVault = async (K, obj) => seal(K, te.encode(JSON.stringify(obj)));
  const decVault = async (K, b) => JSON.parse(td.decode(await open(K, b)));

  // Fresh vault: returns everything to upload plus the legacy code to print (shown once)
  async function createVault(ownerKey, contents, mode = 'sovereign') {
    const K = rand(32), S = rand(32), L = mode === 'standard' ? new Uint8Array(20) : rand(20);
    return {
      K,
      upload: {
        vault: await encVault(K, contents),
        wrappedOwner: await seal(ownerKey, K),
        wrappedRelease: await seal(await releaseKey(S, L), K),
        serverShare: b64(S),
        releaseMode: mode,
      },
      legacyCode: mode === 'standard' ? null : codeEncode(L),
    };
  }
  async function unlockOwner(ownerKey, wrappedOwner) { return open(ownerKey, wrappedOwner); }
  async function unlockRelease(serverShareB64, wrappedRelease, legacyCode, mode) {
    const L = mode === 'standard' ? new Uint8Array(20) : codeDecode(legacyCode);
    return open(await releaseKey(unb64(serverShareB64), L), wrappedRelease);
  }

  // ---------- nominee questions ----------
  const PAIRS = [[0, 1], [0, 2], [1, 2]];
  const ANSWER_ITERS = 200000;
  // Forgiving: capitals, accents, spaces, punctuation and a leading "the" don't matter
  function normAnswer(s) {
    const map = { '\u00df': 'ss', '\u00f8': 'o', '\u00e6': 'ae', '\u0153': 'oe', '\u0142': 'l', '\u0111': 'd', '\u00f0': 'd', '\u00fe': 'th', '\u0131': 'i' };
    return String(s || '').toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[\u00df\u00f8\u00e6\u0153\u0142\u0111\u00f0\u00fe\u0131]/g, c => map[c])
      .replace(/^\s*the\s+/, '').replace(/[^\p{L}\p{N}]/gu, '');
  }
  async function answerHash(norm, saltB64) {
    const base = await crypto.subtle.importKey('raw', te.encode(norm), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: ANSWER_ITERS }, base, 256));
  }
  async function pairKey(hi, hj) {
    const m = new Uint8Array(64); m.set(hi); m.set(hj, 32);
    return new Uint8Array(await crypto.subtle.digest('SHA-256', m));
  }
  async function verifier(L) {
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode('smsv1|' + b64(L))));
    return [...d].map(x => x.toString(16).padStart(2, '0')).join('');
  }
  // Owner side: qs = [{ q, answer, alts: [] }] x3. Returns what the service stores (no answers).
  async function buildNomineeKeys(K, serverShareB64, qs) {
    if (!Array.isArray(qs) || qs.length !== 3) throw new Error('Three questions are needed');
    const S = unb64(serverShareB64), salts = [], variants = [];
    for (const x of qs) {
      if (!String(x.q || '').trim()) throw new Error('Please write all three questions');
      const v = [...new Set([x.answer, ...(x.alts || [])].map(normAnswer).filter(a => a.length >= 2))].slice(0, 5);
      if (!v.length) throw new Error('Each question needs an answer of at least two letters or numbers');
      const salt = b64(rand(16)); salts.push(salt);
      const hs = []; for (const a of v) hs.push(await answerHash(a, salt)); variants.push(hs);
    }
    const wraps = {}, verifiers = {};
    for (const [i, j] of PAIRS) {
      const key = `${i}${j}`; wraps[key] = []; verifiers[key] = [];
      for (const hi of variants[i]) for (const hj of variants[j]) {
        const L = await pairKey(hi, hj);
        wraps[key].push(await seal(await releaseKey(S, L), K)); verifiers[key].push(await verifier(L));
      }
    }
    return { questions: qs.map(x => String(x.q).trim()), salts, wraps, verifiers };
  }
  // Nominee side: three typed answers -> pair keys and proofs (proofs reveal nothing the service could not already test)
  async function answerProofs(salts, answers) {
    const hs = []; for (let i = 0; i < 3; i++) hs.push(await answerHash(normAnswer(answers[i]), salts[i]));
    const keys = {}, proofs = {};
    for (const [i, j] of PAIRS) { const L = await pairKey(hs[i], hs[j]); keys[`${i}${j}`] = L; proofs[`${i}${j}`] = await verifier(L); }
    return { keys, proofs };
  }
  async function unlockWithAnswers(serverShareB64, wrapped, L) { return open(await releaseKey(unb64(serverShareB64), L), wrapped); }

  return { b64, unb64, rand, codeEncode, codeDecode, deriveFromPassword, seal, open, releaseKey, encVault, decVault, createVault, unlockOwner, unlockRelease,
    normAnswer, buildNomineeKeys, answerProofs, unlockWithAnswers };
}
const SMS = SMSFactory();

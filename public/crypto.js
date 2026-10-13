// Save My Secrets: client-side crypto. Everything sensitive is encrypted in the browser.
// Keys:
//   password --PBKDF2(600k)--> authKey (sent to server, hashed again there) + ownerKey (never leaves browser)
//   K  = random vault key; vault JSON is AES-256-GCM encrypted with K
//   wrappedOwner   = AES-GCM(ownerKey, K)
//   S  = server share (held by the service, released only after verification)
//   L  = legacy code (printed, given to the nominee; never sent to the service in sovereign mode)
//   wrappedRelease = AES-GCM(SHA-256(S || L), K)
// The service alone (S) cannot open a vault; the nominee alone (L) cannot either.

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

  return { b64, unb64, rand, codeEncode, codeDecode, deriveFromPassword, seal, open, releaseKey, encVault, decVault, createVault, unlockOwner, unlockRelease };
}
const SMS = SMSFactory();

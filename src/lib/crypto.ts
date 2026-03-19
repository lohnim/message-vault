import nacl from 'tweetnacl'
import algosdk from 'algosdk'

/**
 * Derive a NaCl box keypair by signing a deterministic transaction.
 *
 * Ed25519 signatures are deterministic — the same key signing the same
 * bytes always produces the same 64-byte signature. We build a fixed
 * 0-ALGO transaction (never submitted) and ask the wallet to sign it.
 * SHA-256(signature) → 32-byte seed → X25519 keypair.
 *
 * This works with ALL wallets (Pera, Defly, etc.) since every wallet
 * supports signTransactions, unlike signData which many don't.
 */
export async function deriveEncryptionKeypair(
  signTransactions: (txns: algosdk.Transaction[]) => Promise<(Uint8Array | null)[]>,
  address: string
): Promise<nacl.BoxKeyPair> {
  // Use real mainnet genesis info so the wallet accepts it.
  // firstValid/lastValid are in the past so this can never be submitted.
  const MAINNET_GENESIS_HASH = base64ToUint8('wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=')
  const fixedParams: algosdk.SuggestedParams = {
    fee: 0,
    firstValid: 1,
    lastValid: 2,
    genesisID: 'mainnet-v1.0',
    genesisHash: MAINNET_GENESIS_HASH,
    flatFee: true,
    minFee: 0,
  }

  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: address,
    receiver: address,
    amount: 0,
    suggestedParams: fixedParams,
    note: new TextEncoder().encode('messagevault-keygen-v1'),
  })

  const signed = await signTransactions([txn])
  const signedBytes = signed[0]
  if (!signedBytes) throw new Error('Transaction signing was rejected')

  // Extract the 64-byte Ed25519 signature from the signed transaction
  const decoded = algosdk.decodeSignedTransaction(signedBytes)
  const signature = decoded.sig
  if (!signature) throw new Error('No signature found in signed transaction')

  // SHA-256(signature) → 32-byte seed → X25519 keypair
  const hash = await crypto.subtle.digest(
    'SHA-256',
    (signature as Uint8Array).buffer as ArrayBuffer
  )
  const seed = new Uint8Array(hash)

  return nacl.box.keyPair.fromSecretKey(seed)
}

/**
 * Encrypt a message for a recipient using NaCl box (X25519 + XSalsa20-Poly1305).
 * Uses an ephemeral keypair for forward secrecy.
 */
export function encryptMessage(
  plaintext: string,
  receiverPubKey: Uint8Array
): { ciphertext: Uint8Array; nonce: Uint8Array; ephemeralPubKey: Uint8Array } {
  const ephemeral = nacl.box.keyPair()
  const nonce = nacl.randomBytes(nacl.box.nonceLength)
  const messageBytes = new TextEncoder().encode(plaintext)

  const ciphertext = nacl.box(messageBytes, nonce, receiverPubKey, ephemeral.secretKey)
  if (!ciphertext) throw new Error('Encryption failed')

  return { ciphertext, nonce, ephemeralPubKey: ephemeral.publicKey }
}

/**
 * Decrypt a message using the recipient's derived secret key.
 */
export function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  ephemeralPubKey: Uint8Array,
  mySecretKey: Uint8Array
): string | null {
  const plaintext = nacl.box.open(ciphertext, nonce, ephemeralPubKey, mySecretKey)
  if (!plaintext) return null
  return new TextDecoder().decode(plaintext)
}

/**
 * Encode an encrypted DM payload as a transaction note.
 * Format: "messagevault:" + JSON with base64-encoded fields
 */
export function encodeDMNote(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  ephemeralPubKey: Uint8Array
): Uint8Array {
  const payload = {
    app: 'messagevault',
    type: 'dm',
    ct: uint8ToBase64(ciphertext),
    n: uint8ToBase64(nonce),
    ek: uint8ToBase64(ephemeralPubKey),
  }
  return new TextEncoder().encode(`messagevault:${JSON.stringify(payload)}`)
}

/**
 * Encode a registration note (publishes encryption public key on-chain).
 */
export function encodeRegisterNote(encryptionPubKey: Uint8Array, username?: string): Uint8Array {
  const payload: Record<string, string> = {
    app: 'messagevault',
    type: 'register',
    pk: uint8ToBase64(encryptionPubKey),
  }
  if (username) payload.name = username
  return new TextEncoder().encode(`messagevault:${JSON.stringify(payload)}`)
}

/**
 * Encrypt a message for a recipient using their registered public key (base64).
 * Uses ephemeral keypair for forward secrecy.
 */
export function encryptForRegisteredKey(
  plaintext: string,
  receiverPubKeyB64: string
): Uint8Array {
  const receiverPubKey = base64ToUint8(receiverPubKeyB64)
  const { ciphertext, nonce, ephemeralPubKey } = encryptMessage(plaintext, receiverPubKey)
  return encodeDMNote(ciphertext, nonce, ephemeralPubKey)
}

// --- Keypair persistence (localStorage) ---

const STORAGE_KEY_PREFIX = 'messagevault-keypair-'

export function saveKeypair(address: string, kp: nacl.BoxKeyPair) {
  const data = {
    pk: uint8ToBase64(kp.publicKey),
    sk: uint8ToBase64(kp.secretKey),
  }
  localStorage.setItem(STORAGE_KEY_PREFIX + address, JSON.stringify(data))
}

export function loadKeypair(address: string): nacl.BoxKeyPair | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_PREFIX + address)
    if (!raw) return null
    const data = JSON.parse(raw)
    const publicKey = base64ToUint8(data.pk)
    const secretKey = base64ToUint8(data.sk)
    return { publicKey, secretKey }
  } catch {
    return null
  }
}

export function clearKeypair(address: string) {
  localStorage.removeItem(STORAGE_KEY_PREFIX + address)
}

// --- ECDH Shared Key Encryption (v2) ---

/** In-memory cache of derived shared keys to avoid recomputing per message */
const sharedKeyCache = new Map<string, Uint8Array>()

function sharedKeyCacheKey(theirPubKey: Uint8Array, mySecretKey: Uint8Array): string {
  return uint8ToBase64(theirPubKey) + ':' + uint8ToBase64(mySecretKey)
}

/**
 * Derive a shared symmetric key via X25519 ECDH (nacl.box.before).
 * Result is cached in memory for the session.
 */
export function deriveSharedKey(theirPubKey: Uint8Array, mySecretKey: Uint8Array): Uint8Array {
  const cacheKey = sharedKeyCacheKey(theirPubKey, mySecretKey)
  const cached = sharedKeyCache.get(cacheKey)
  if (cached) return cached
  const shared = nacl.box.before(theirPubKey, mySecretKey)
  sharedKeyCache.set(cacheKey, shared)
  return shared
}

/**
 * Encrypt plaintext with a shared symmetric key (XSalsa20-Poly1305 via nacl.secretbox).
 */
export function encryptWithSharedKey(
  plaintext: string,
  sharedKey: Uint8Array
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  const messageBytes = new TextEncoder().encode(plaintext)
  const ciphertext = nacl.secretbox(messageBytes, nonce, sharedKey)
  if (!ciphertext) throw new Error('Encryption failed')
  return { ciphertext, nonce }
}

/**
 * Decrypt ciphertext with a shared symmetric key.
 */
export function decryptWithSharedKey(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  sharedKey: Uint8Array
): string | null {
  const plaintext = nacl.secretbox.open(ciphertext, nonce, sharedKey)
  if (!plaintext) return null
  return new TextDecoder().decode(plaintext)
}

/**
 * Encode a v2 DM note (ECDH shared-key encryption, no ephemeral key needed).
 */
export function encodeDMNoteV2(
  ciphertext: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const payload = {
    app: 'messagevault',
    type: 'dm',
    v: 2,
    ct: uint8ToBase64(ciphertext),
    n: uint8ToBase64(nonce),
  }
  return new TextEncoder().encode(`messagevault:${JSON.stringify(payload)}`)
}

/**
 * One-shot ECDH encrypt: derive shared key from peer's public key and my secret key,
 * then encrypt and encode as a v2 note.
 */
export function encryptForPeer(
  plaintext: string,
  receiverPubKeyB64: string,
  mySecretKey: Uint8Array
): Uint8Array {
  const receiverPubKey = base64ToUint8(receiverPubKeyB64)
  const sharedKey = deriveSharedKey(receiverPubKey, mySecretKey)
  const { ciphertext, nonce } = encryptWithSharedKey(plaintext, sharedKey)
  return encodeDMNoteV2(ciphertext, nonce)
}

/**
 * Universal DM decrypt: detects v1 (has `ek` field) vs v2 (has `v: 2`) and uses
 * the appropriate decryption method.
 *
 * For v1: uses ephemeral public key from the message (only receiver can decrypt).
 * For v2: derives ECDH shared key from peer's public key (both parties can decrypt).
 */
export function decryptDM(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload: any,
  mySecretKey: Uint8Array,
  peerPubKeyB64?: string
): string | null {
  const { ct, n } = payload
  if (!ct || !n) return null

  if (payload.v === 2) {
    // v2: ECDH shared key decryption
    if (!peerPubKeyB64) return null
    const peerPubKey = base64ToUint8(peerPubKeyB64)
    const sharedKey = deriveSharedKey(peerPubKey, mySecretKey)
    return decryptWithSharedKey(base64ToUint8(ct), base64ToUint8(n), sharedKey)
  }

  // v1: ephemeral key decryption
  const { ek } = payload
  if (!ek) return null
  return decryptMessage(base64ToUint8(ct), base64ToUint8(n), base64ToUint8(ek), mySecretKey)
}

// --- Base64 helpers ---

export function uint8ToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

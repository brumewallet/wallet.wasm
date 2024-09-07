/* tslint:disable */
/* eslint-disable */
/**
* @param {Memory} data
* @returns {Memory}
*/
export function sha1(data: Memory): Memory;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base16_encode_lower(bytes: Memory): string;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base16_encode_upper(bytes: Memory): string;
/**
* @param {string} text
* @returns {Memory}
*/
export function base16_decode_mixed(text: string): Memory;
/**
* @param {string} text
* @returns {Memory}
*/
export function base16_decode_lower(text: string): Memory;
/**
* @param {string} text
* @returns {Memory}
*/
export function base16_decode_upper(text: string): Memory;
/**
* @param {Memory} data
* @returns {Memory}
*/
export function keccak256(data: Memory): Memory;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64_encode_padded(bytes: Memory): string;
/**
* @param {string} text
* @returns {Memory}
*/
export function base64_decode_padded(text: string): Memory;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64_encode_unpadded(bytes: Memory): string;
/**
* @param {string} text
* @returns {Memory}
*/
export function base64_decode_unpadded(text: string): Memory;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64url_encode_padded(bytes: Memory): string;
/**
* @param {string} text
* @returns {Memory}
*/
export function base64url_decode_padded(text: string): Memory;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64url_encode_unpadded(bytes: Memory): string;
/**
* @param {string} text
* @returns {Memory}
*/
export function base64url_decode_unpadded(text: string): Memory;
/**
* @param {Memory} data
* @returns {Memory}
*/
export function ripemd160(data: Memory): Memory;
/**
* @param {Memory} bytes
* @returns {string}
*/
export function base58_encode(bytes: Memory): string;
/**
* @param {string} text
* @returns {Memory}
*/
export function base58_decode(text: string): Memory;
/**
*/
export class ChaCha20Poly1305Cipher {
  [Symbol.dispose](): void;
/**
* @param {Memory} key
*/
  constructor(key: Memory);
/**
* @param {Memory} message
* @param {Memory} nonce
* @returns {Memory}
*/
  encrypt(message: Memory, nonce: Memory): Memory;
/**
* @param {Memory} message
* @param {Memory} nonce
* @returns {Memory}
*/
  decrypt(message: Memory, nonce: Memory): Memory;
}
/**
*/
export class Ed25519Signature {
  [Symbol.dispose](): void;
/**
* @param {Memory} bytes
*/
  constructor(bytes: Memory);
/**
* @param {Memory} bytes
* @returns {Ed25519Signature}
*/
  static from_bytes(bytes: Memory): Ed25519Signature;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
/**
* @returns {Memory}
*/
  r_bytes(): Memory;
/**
* @returns {Memory}
*/
  s_bytes(): Memory;
}
/**
*/
export class Ed25519SigningKey {
  [Symbol.dispose](): void;
/**
*/
  constructor();
/**
* @returns {Ed25519SigningKey}
*/
  static random(): Ed25519SigningKey;
/**
* @param {Memory} bytes
* @returns {Ed25519SigningKey}
*/
  static from_bytes(bytes: Memory): Ed25519SigningKey;
/**
* @param {Memory} bytes
* @returns {Ed25519SigningKey}
*/
  static from_keypair_bytes(bytes: Memory): Ed25519SigningKey;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
/**
* @returns {Memory}
*/
  to_keypair_bytes(): Memory;
/**
* @returns {Ed25519VerifyingKey}
*/
  verifying_key(): Ed25519VerifyingKey;
/**
* @param {Memory} bytes
* @returns {Ed25519Signature}
*/
  sign(bytes: Memory): Ed25519Signature;
/**
* @param {Memory} bytes
* @param {Ed25519Signature} signature
* @returns {boolean}
*/
  verify(bytes: Memory, signature: Ed25519Signature): boolean;
/**
* @param {Memory} bytes
* @param {Ed25519Signature} signature
* @returns {boolean}
*/
  verify_strict(bytes: Memory, signature: Ed25519Signature): boolean;
}
/**
*/
export class Ed25519VerifyingKey {
  [Symbol.dispose](): void;
/**
* @param {Memory} bytes
*/
  constructor(bytes: Memory);
/**
* @param {Memory} bytes
* @returns {Ed25519VerifyingKey}
*/
  static from_bytes(bytes: Memory): Ed25519VerifyingKey;
/**
* @returns {boolean}
*/
  is_weak(): boolean;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
/**
* @param {Memory} bytes
* @param {Ed25519Signature} signature
* @returns {boolean}
*/
  verify(bytes: Memory, signature: Ed25519Signature): boolean;
/**
* @param {Memory} bytes
* @param {Ed25519Signature} signature
* @returns {boolean}
*/
  verify_strict(bytes: Memory, signature: Ed25519Signature): boolean;
}
/**
*/
export class Keccak256Hasher {
  [Symbol.dispose](): void;
/**
*/
  constructor();
/**
* @returns {Keccak256Hasher}
*/
  clone(): Keccak256Hasher;
/**
* @param {Memory} data
*/
  update(data: Memory): void;
/**
* @returns {Memory}
*/
  finalize(): Memory;
}
/**
*/
export class Memory {
  [Symbol.dispose](): void;
/**
* @param {Uint8Array} inner
*/
  constructor(inner: Uint8Array);
/**
* @returns {number}
*/
  ptr(): number;
/**
* @returns {number}
*/
  len(): number;
/**
* @returns {Uint8Array}
*/
  get bytes(): Uint8Array;
}
/**
*/
export class NetworkMixin {
  [Symbol.dispose](): void;
/**
* @param {Memory} chain_memory
* @param {Memory} contract_memory
* @param {Memory} receiver_nonce
* @param {Memory} nonce_memory
*/
  constructor(chain_memory: Memory, contract_memory: Memory, receiver_nonce: Memory, nonce_memory: Memory);
/**
* @param {Memory} minimum_memory
* @returns {NetworkSecret}
*/
  generate(minimum_memory: Memory): NetworkSecret;
/**
* @param {Memory} secret_memory
* @returns {Memory}
*/
  verify_secret(secret_memory: Memory): Memory;
/**
* @param {Memory} proof_memory
* @returns {Memory}
*/
  verify_proof(proof_memory: Memory): Memory;
}
/**
*/
export class NetworkSecret {
  [Symbol.dispose](): void;
/**
* @returns {Memory}
*/
  to_secret(): Memory;
/**
* @returns {Memory}
*/
  to_proof(): Memory;
/**
* @returns {Memory}
*/
  to_value(): Memory;
}
/**
*/
export class Ripemd160Hasher {
  [Symbol.dispose](): void;
/**
*/
  constructor();
/**
* @returns {Ripemd160Hasher}
*/
  clone(): Ripemd160Hasher;
/**
* @param {Memory} data
*/
  update(data: Memory): void;
/**
* @returns {Memory}
*/
  finalize(): Memory;
}
/**
*/
export class Secp256k1SignatureAndRecovery {
  [Symbol.dispose](): void;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
}
/**
*/
export class Secp256k1SigningKey {
  [Symbol.dispose](): void;
/**
*/
  constructor();
/**
* @returns {Secp256k1SigningKey}
*/
  static random(): Secp256k1SigningKey;
/**
* @param {Memory} input
* @returns {Secp256k1SigningKey}
*/
  static from_bytes(input: Memory): Secp256k1SigningKey;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
/**
* @returns {Secp256k1VerifyingKey}
*/
  verifying_key(): Secp256k1VerifyingKey;
/**
* @param {Memory} hashed
* @returns {Secp256k1SignatureAndRecovery}
*/
  sign_prehash_recoverable(hashed: Memory): Secp256k1SignatureAndRecovery;
}
/**
*/
export class Secp256k1VerifyingKey {
  [Symbol.dispose](): void;
/**
* @param {Memory} input
* @returns {Secp256k1VerifyingKey}
*/
  static from_sec1_bytes(input: Memory): Secp256k1VerifyingKey;
/**
* @param {Memory} hashed
* @param {Secp256k1SignatureAndRecovery} signature
* @returns {Secp256k1VerifyingKey}
*/
  static recover_from_prehash(hashed: Memory, signature: Secp256k1SignatureAndRecovery): Secp256k1VerifyingKey;
/**
* @returns {Memory}
*/
  to_sec1_compressed_bytes(): Memory;
/**
* @returns {Memory}
*/
  to_sec1_uncompressed_bytes(): Memory;
}
/**
*/
export class Sha1Hasher {
  [Symbol.dispose](): void;
/**
*/
  constructor();
/**
* @returns {Sha1Hasher}
*/
  clone(): Sha1Hasher;
/**
* @param {Memory} data
*/
  update(data: Memory): void;
/**
* @returns {Memory}
*/
  finalize(): Memory;
}
/**
*/
export class X25519PublicKey {
  [Symbol.dispose](): void;
/**
* @param {Memory} bytes
*/
  constructor(bytes: Memory);
/**
* @param {Memory} bytes
* @returns {X25519PublicKey}
*/
  static from_bytes(bytes: Memory): X25519PublicKey;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
}
/**
*/
export class X25519SharedSecret {
  [Symbol.dispose](): void;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
/**
* @returns {boolean}
*/
  was_contributory(): boolean;
}
/**
*/
export class X25519StaticSecret {
  [Symbol.dispose](): void;
/**
*/
  constructor();
/**
* @param {Memory} bytes
* @returns {X25519StaticSecret}
*/
  static from_bytes(bytes: Memory): X25519StaticSecret;
/**
* @returns {Memory}
*/
  to_bytes(): Memory;
/**
* @param {X25519PublicKey} other
* @returns {X25519SharedSecret}
*/
  diffie_hellman(other: X25519PublicKey): X25519SharedSecret;
/**
* @returns {X25519PublicKey}
*/
  to_public(): X25519PublicKey;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_x25519sharedsecret_free: (a: number, b: number) => void;
  readonly x25519sharedsecret_to_bytes: (a: number) => number;
  readonly x25519sharedsecret_was_contributory: (a: number) => number;
  readonly __wbg_x25519publickey_free: (a: number, b: number) => void;
  readonly x25519publickey_from_bytes: (a: number, b: number) => void;
  readonly x25519publickey_to_bytes: (a: number) => number;
  readonly x25519staticsecret_random: () => number;
  readonly x25519staticsecret_from_bytes: (a: number, b: number) => void;
  readonly x25519staticsecret_to_bytes: (a: number) => number;
  readonly x25519staticsecret_diffie_hellman: (a: number, b: number) => number;
  readonly x25519staticsecret_to_public: (a: number) => number;
  readonly x25519publickey_new: (a: number, b: number) => void;
  readonly __wbg_x25519staticsecret_free: (a: number, b: number) => void;
  readonly sha1: (a: number) => number;
  readonly __wbg_sha1hasher_free: (a: number, b: number) => void;
  readonly sha1hasher_new: () => number;
  readonly sha1hasher_clone: (a: number) => number;
  readonly sha1hasher_update: (a: number, b: number) => void;
  readonly sha1hasher_finalize: (a: number) => number;
  readonly __wbg_secp256k1signatureandrecovery_free: (a: number, b: number) => void;
  readonly secp256k1signatureandrecovery_to_bytes: (a: number) => number;
  readonly __wbg_secp256k1verifyingkey_free: (a: number, b: number) => void;
  readonly secp256k1verifyingkey_from_sec1_bytes: (a: number, b: number) => void;
  readonly secp256k1verifyingkey_recover_from_prehash: (a: number, b: number, c: number) => void;
  readonly secp256k1verifyingkey_to_sec1_compressed_bytes: (a: number) => number;
  readonly secp256k1verifyingkey_to_sec1_uncompressed_bytes: (a: number) => number;
  readonly __wbg_secp256k1signingkey_free: (a: number, b: number) => void;
  readonly secp256k1signingkey_new: () => number;
  readonly secp256k1signingkey_from_bytes: (a: number, b: number) => void;
  readonly secp256k1signingkey_to_bytes: (a: number) => number;
  readonly secp256k1signingkey_verifying_key: (a: number) => number;
  readonly secp256k1signingkey_sign_prehash_recoverable: (a: number, b: number, c: number) => void;
  readonly secp256k1signingkey_random: () => number;
  readonly ripemd160: (a: number) => number;
  readonly __wbg_ripemd160hasher_free: (a: number, b: number) => void;
  readonly ripemd160hasher_new: () => number;
  readonly ripemd160hasher_clone: (a: number) => number;
  readonly ripemd160hasher_update: (a: number, b: number) => void;
  readonly ripemd160hasher_finalize: (a: number) => number;
  readonly __wbg_networksecret_free: (a: number, b: number) => void;
  readonly networksecret_to_secret: (a: number) => number;
  readonly networksecret_to_proof: (a: number) => number;
  readonly networksecret_to_value: (a: number) => number;
  readonly __wbg_networkmixin_free: (a: number, b: number) => void;
  readonly networkmixin_new: (a: number, b: number, c: number, d: number) => number;
  readonly networkmixin_generate: (a: number, b: number) => number;
  readonly networkmixin_verify_secret: (a: number, b: number) => number;
  readonly networkmixin_verify_proof: (a: number, b: number) => number;
  readonly keccak256: (a: number) => number;
  readonly __wbg_keccak256hasher_free: (a: number, b: number) => void;
  readonly keccak256hasher_new: () => number;
  readonly keccak256hasher_clone: (a: number) => number;
  readonly keccak256hasher_update: (a: number, b: number) => void;
  readonly keccak256hasher_finalize: (a: number) => number;
  readonly __wbg_ed25519signature_free: (a: number, b: number) => void;
  readonly ed25519signature_from_bytes: (a: number, b: number) => void;
  readonly ed25519signature_to_bytes: (a: number) => number;
  readonly ed25519signature_r_bytes: (a: number) => number;
  readonly ed25519signature_s_bytes: (a: number) => number;
  readonly ed25519signature_new: (a: number, b: number) => void;
  readonly __wbg_ed25519signingkey_free: (a: number, b: number) => void;
  readonly ed25519signingkey_new: () => number;
  readonly ed25519signingkey_from_bytes: (a: number, b: number) => void;
  readonly ed25519signingkey_from_keypair_bytes: (a: number, b: number) => void;
  readonly ed25519signingkey_to_bytes: (a: number) => number;
  readonly ed25519signingkey_to_keypair_bytes: (a: number) => number;
  readonly ed25519signingkey_verifying_key: (a: number) => number;
  readonly ed25519signingkey_sign: (a: number, b: number) => number;
  readonly ed25519signingkey_verify: (a: number, b: number, c: number) => number;
  readonly ed25519signingkey_verify_strict: (a: number, b: number, c: number) => number;
  readonly ed25519signingkey_random: () => number;
  readonly __wbg_ed25519verifyingkey_free: (a: number, b: number) => void;
  readonly ed25519verifyingkey_from_bytes: (a: number, b: number) => void;
  readonly ed25519verifyingkey_is_weak: (a: number) => number;
  readonly ed25519verifyingkey_to_bytes: (a: number) => number;
  readonly ed25519verifyingkey_verify: (a: number, b: number, c: number) => number;
  readonly ed25519verifyingkey_verify_strict: (a: number, b: number, c: number) => number;
  readonly ed25519verifyingkey_new: (a: number, b: number) => void;
  readonly __wbg_chacha20poly1305cipher_free: (a: number, b: number) => void;
  readonly chacha20poly1305cipher_new: (a: number, b: number) => void;
  readonly chacha20poly1305cipher_encrypt: (a: number, b: number, c: number, d: number) => void;
  readonly chacha20poly1305cipher_decrypt: (a: number, b: number, c: number, d: number) => void;
  readonly base64_encode_padded: (a: number, b: number) => void;
  readonly base64_decode_padded: (a: number, b: number, c: number) => void;
  readonly base64_encode_unpadded: (a: number, b: number) => void;
  readonly base64_decode_unpadded: (a: number, b: number, c: number) => void;
  readonly base64url_encode_padded: (a: number, b: number) => void;
  readonly base64url_decode_padded: (a: number, b: number, c: number) => void;
  readonly base64url_encode_unpadded: (a: number, b: number) => void;
  readonly base64url_decode_unpadded: (a: number, b: number, c: number) => void;
  readonly base58_encode: (a: number, b: number) => void;
  readonly base58_decode: (a: number, b: number, c: number) => void;
  readonly base16_encode_lower: (a: number, b: number) => void;
  readonly base16_encode_upper: (a: number, b: number) => void;
  readonly base16_decode_mixed: (a: number, b: number, c: number) => void;
  readonly base16_decode_lower: (a: number, b: number, c: number) => void;
  readonly base16_decode_upper: (a: number, b: number, c: number) => void;
  readonly __wbg_memory_free: (a: number, b: number) => void;
  readonly memory_new: (a: number, b: number) => number;
  readonly memory_ptr: (a: number) => number;
  readonly memory_len: (a: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

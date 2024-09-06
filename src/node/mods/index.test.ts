import { Memory, WalletWasm, base16_decode_mixed, base16_encode_lower } from "../index.js"

await WalletWasm.initBundled()

/**
 * Chain ID
 */
const chainIdBigInt = 100n
const chainIdBase16 = chainIdBigInt.toString(16).padStart(64, "0")
using chainIdMemory = base16_decode_mixed(chainIdBase16)

/**
 * Contract address
 */
const contractZeroHex = "0xF1eC047cbd662607BBDE9Badd572cf0A23E1130B"
const contractBase16 = contractZeroHex.slice(2).padStart(64, "0")
using contractMemory = base16_decode_mixed(contractBase16)

/**
 * Receiver address
 */
const receiverZeroHex = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
const receiverBase16 = receiverZeroHex.slice(2).padStart(64, "0")
using receiverMemory = base16_decode_mixed(receiverBase16)

/**
 * Nonce
 */
const nonceBytes = crypto.getRandomValues(new Uint8Array(32))
using nonceMemory = new Memory(nonceBytes)
const nonceBase16 = base16_encode_lower(nonceMemory)

/**
 * Price
 */
const minimumBigInt = 100000n
const minimumBase16 = minimumBigInt.toString(16).padStart(64, "0")
using minimumMemory = base16_decode_mixed(minimumBase16)

using mixin = new WalletWasm.NetworkMixin(chainIdMemory, contractMemory, receiverMemory, nonceMemory)

const start = performance.now()
using generated = mixin.generate(minimumMemory)
const end = performance.now()

using secretMemory = generated.to_secret()
const secretBase16 = base16_encode_lower(secretMemory)

using proofMemory = generated.to_proof()
const proofBase16 = base16_encode_lower(proofMemory)

const valueBase16 = base16_encode_lower(generated.to_value())
const valueBigInt = BigInt("0x" + valueBase16)

console.log(valueBigInt, secretBase16, proofBase16)

console.log(`Generated ${valueBigInt} wei in ${end - start}ms`)
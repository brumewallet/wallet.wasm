let wasm;

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}
/**
* @param {Memory} data
* @returns {Memory}
*/
export function sha1(data) {
    _assertClass(data, Memory);
    const ret = wasm.sha1(data.__wbg_ptr);
    return Memory.__wrap(ret);
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base16_encode_lower(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base16_encode_lower(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base16_encode_upper(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base16_encode_upper(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}
/**
* @param {string} text
* @returns {Memory}
*/
export function base16_decode_mixed(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base16_decode_mixed(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base16_decode_lower(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base16_decode_lower(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base16_decode_upper(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base16_decode_upper(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {Memory} data
* @returns {Memory}
*/
export function keccak256(data) {
    _assertClass(data, Memory);
    const ret = wasm.keccak256(data.__wbg_ptr);
    return Memory.__wrap(ret);
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64_encode_padded(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base64_encode_padded(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base64_decode_padded(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base64_decode_padded(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64_encode_unpadded(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base64_encode_unpadded(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base64_decode_unpadded(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base64_decode_unpadded(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64url_encode_padded(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base64url_encode_padded(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base64url_decode_padded(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base64url_decode_padded(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base64url_encode_unpadded(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base64url_encode_unpadded(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base64url_decode_unpadded(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base64url_decode_unpadded(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {Memory} data
* @returns {Memory}
*/
export function ripemd160(data) {
    _assertClass(data, Memory);
    const ret = wasm.ripemd160(data.__wbg_ptr);
    return Memory.__wrap(ret);
}

/**
* @param {Memory} bytes
* @returns {string}
*/
export function base58_encode(bytes) {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(bytes, Memory);
        wasm.base58_encode(retptr, bytes.__wbg_ptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
* @param {string} text
* @returns {Memory}
*/
export function base58_decode(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.base58_decode(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return Memory.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

const ChaCha20Poly1305CipherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_chacha20poly1305cipher_free(ptr >>> 0, 1));
/**
*/
export class ChaCha20Poly1305Cipher {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ChaCha20Poly1305CipherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_chacha20poly1305cipher_free(ptr, 0);
    }
    /**
    * @param {Memory} key
    */
    constructor(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, Memory);
            wasm.chacha20poly1305cipher_new(retptr, key.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            ChaCha20Poly1305CipherFinalization;
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} message
    * @param {Memory} nonce
    * @returns {Memory}
    */
    encrypt(message, nonce) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(message, Memory);
            _assertClass(nonce, Memory);
            wasm.chacha20poly1305cipher_encrypt(retptr, this.__wbg_ptr, message.__wbg_ptr, nonce.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Memory.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} message
    * @param {Memory} nonce
    * @returns {Memory}
    */
    decrypt(message, nonce) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(message, Memory);
            _assertClass(nonce, Memory);
            wasm.chacha20poly1305cipher_decrypt(retptr, this.__wbg_ptr, message.__wbg_ptr, nonce.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Memory.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}

const Ed25519SignatureFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ed25519signature_free(ptr >>> 0, 1));
/**
*/
export class Ed25519Signature {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Ed25519Signature.prototype);
        obj.__wbg_ptr = ptr;
        Ed25519SignatureFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Ed25519SignatureFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ed25519signature_free(ptr, 0);
    }
    /**
    * @param {Memory} bytes
    */
    constructor(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.ed25519signature_new(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            Ed25519SignatureFinalization;
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} bytes
    * @returns {Ed25519Signature}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.ed25519signature_from_bytes(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Ed25519Signature.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.ed25519signature_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Memory}
    */
    r_bytes() {
        const ret = wasm.ed25519signature_r_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Memory}
    */
    s_bytes() {
        const ret = wasm.ed25519signature_s_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Ed25519SigningKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ed25519signingkey_free(ptr >>> 0, 1));
/**
*/
export class Ed25519SigningKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Ed25519SigningKey.prototype);
        obj.__wbg_ptr = ptr;
        Ed25519SigningKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Ed25519SigningKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ed25519signingkey_free(ptr, 0);
    }
    /**
    */
    constructor() {
        const ret = wasm.ed25519signingkey_new();
        this.__wbg_ptr = ret >>> 0;
        Ed25519SigningKeyFinalization;
        return this;
    }
    /**
    * @returns {Ed25519SigningKey}
    */
    static random() {
        const ret = wasm.ed25519signingkey_new();
        return Ed25519SigningKey.__wrap(ret);
    }
    /**
    * @param {Memory} bytes
    * @returns {Ed25519SigningKey}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.ed25519signingkey_from_bytes(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Ed25519SigningKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} bytes
    * @returns {Ed25519SigningKey}
    */
    static from_keypair_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.ed25519signingkey_from_keypair_bytes(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Ed25519SigningKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.ed25519signingkey_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Memory}
    */
    to_keypair_bytes() {
        const ret = wasm.ed25519signingkey_to_keypair_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Ed25519VerifyingKey}
    */
    verifying_key() {
        const ret = wasm.ed25519signingkey_verifying_key(this.__wbg_ptr);
        return Ed25519VerifyingKey.__wrap(ret);
    }
    /**
    * @param {Memory} bytes
    * @returns {Ed25519Signature}
    */
    sign(bytes) {
        _assertClass(bytes, Memory);
        const ret = wasm.ed25519signingkey_sign(this.__wbg_ptr, bytes.__wbg_ptr);
        return Ed25519Signature.__wrap(ret);
    }
    /**
    * @param {Memory} bytes
    * @param {Ed25519Signature} signature
    * @returns {boolean}
    */
    verify(bytes, signature) {
        _assertClass(bytes, Memory);
        _assertClass(signature, Ed25519Signature);
        const ret = wasm.ed25519signingkey_verify(this.__wbg_ptr, bytes.__wbg_ptr, signature.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * @param {Memory} bytes
    * @param {Ed25519Signature} signature
    * @returns {boolean}
    */
    verify_strict(bytes, signature) {
        _assertClass(bytes, Memory);
        _assertClass(signature, Ed25519Signature);
        const ret = wasm.ed25519signingkey_verify_strict(this.__wbg_ptr, bytes.__wbg_ptr, signature.__wbg_ptr);
        return ret !== 0;
    }
}

const Ed25519VerifyingKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ed25519verifyingkey_free(ptr >>> 0, 1));
/**
*/
export class Ed25519VerifyingKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Ed25519VerifyingKey.prototype);
        obj.__wbg_ptr = ptr;
        Ed25519VerifyingKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Ed25519VerifyingKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ed25519verifyingkey_free(ptr, 0);
    }
    /**
    * @param {Memory} bytes
    */
    constructor(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.ed25519verifyingkey_new(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            Ed25519VerifyingKeyFinalization;
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} bytes
    * @returns {Ed25519VerifyingKey}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.ed25519verifyingkey_from_bytes(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Ed25519VerifyingKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {boolean}
    */
    is_weak() {
        const ret = wasm.ed25519verifyingkey_is_weak(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.ed25519verifyingkey_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @param {Memory} bytes
    * @param {Ed25519Signature} signature
    * @returns {boolean}
    */
    verify(bytes, signature) {
        _assertClass(bytes, Memory);
        _assertClass(signature, Ed25519Signature);
        const ret = wasm.ed25519verifyingkey_verify(this.__wbg_ptr, bytes.__wbg_ptr, signature.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * @param {Memory} bytes
    * @param {Ed25519Signature} signature
    * @returns {boolean}
    */
    verify_strict(bytes, signature) {
        _assertClass(bytes, Memory);
        _assertClass(signature, Ed25519Signature);
        const ret = wasm.ed25519verifyingkey_verify_strict(this.__wbg_ptr, bytes.__wbg_ptr, signature.__wbg_ptr);
        return ret !== 0;
    }
}

const Keccak256HasherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keccak256hasher_free(ptr >>> 0, 1));
/**
*/
export class Keccak256Hasher {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Keccak256Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Keccak256HasherFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Keccak256HasherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keccak256hasher_free(ptr, 0);
    }
    /**
    */
    constructor() {
        const ret = wasm.keccak256hasher_new();
        this.__wbg_ptr = ret >>> 0;
        Keccak256HasherFinalization;
        return this;
    }
    /**
    * @returns {Keccak256Hasher}
    */
    clone() {
        const ret = wasm.keccak256hasher_clone(this.__wbg_ptr);
        return Keccak256Hasher.__wrap(ret);
    }
    /**
    * @param {Memory} data
    */
    update(data) {
        _assertClass(data, Memory);
        wasm.keccak256hasher_update(this.__wbg_ptr, data.__wbg_ptr);
    }
    /**
    * @returns {Memory}
    */
    finalize() {
        const ret = wasm.keccak256hasher_finalize(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const MemoryFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_memory_free(ptr >>> 0, 1));
/**
*/
export class Memory {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Memory.prototype);
        obj.__wbg_ptr = ptr;
        MemoryFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        this.__wbg_ptr0 = 0;
        this.__wbg_len0 = 0;
        MemoryFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_memory_free(ptr, 0);
    }
    /**
    * @param {Uint8Array} inner
    */
    constructor(inner) {
        const ptr0 = passArray8ToWasm0(inner, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.memory_new(ptr0, len0);
        this.__wbg_ptr = ret >>> 0;
        this.__wbg_ptr0 = ptr0 >>> 0;
        this.__wbg_len0 = len0 >>> 0;
        MemoryFinalization;
        return this;
    }
    /**
    * @returns {number}
    */
    ptr() {
        const ret = wasm.memory_ptr(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.memory_len(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    get ptr0() {
        return this.__wbg_ptr0 ??= this.ptr();
    }
    /**
    * @returns {number}
    */
    get len0() {
        return this.__wbg_len0 ??= this.len();
    }
    /**
    * @returns {Uint8Array}
    */
    get bytes() {
        return getUint8ArrayMemory0().subarray(this.ptr0, this.ptr0 + this.len0);
    }
}

const NetworkMixinFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_networkmixin_free(ptr >>> 0, 1));
/**
*/
export class NetworkMixin {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        NetworkMixinFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_networkmixin_free(ptr, 0);
    }
    /**
    * @param {Memory} chain_memory
    * @param {Memory} contract_memory
    * @param {Memory} receiver_nonce
    * @param {Memory} nonce_memory
    */
    constructor(chain_memory, contract_memory, receiver_nonce, nonce_memory) {
        _assertClass(chain_memory, Memory);
        _assertClass(contract_memory, Memory);
        _assertClass(receiver_nonce, Memory);
        _assertClass(nonce_memory, Memory);
        const ret = wasm.networkmixin_new(chain_memory.__wbg_ptr, contract_memory.__wbg_ptr, receiver_nonce.__wbg_ptr, nonce_memory.__wbg_ptr);
        this.__wbg_ptr = ret >>> 0;
        NetworkMixinFinalization;
        return this;
    }
    /**
    * @param {Memory} minimum_memory
    * @returns {NetworkSecret}
    */
    generate(minimum_memory) {
        _assertClass(minimum_memory, Memory);
        const ret = wasm.networkmixin_generate(this.__wbg_ptr, minimum_memory.__wbg_ptr);
        return NetworkSecret.__wrap(ret);
    }
    /**
    * @param {Memory} secret_memory
    * @returns {Memory}
    */
    verify_secret(secret_memory) {
        _assertClass(secret_memory, Memory);
        const ret = wasm.networkmixin_verify_secret(this.__wbg_ptr, secret_memory.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @param {Memory} proof_memory
    * @returns {Memory}
    */
    verify_proof(proof_memory) {
        _assertClass(proof_memory, Memory);
        const ret = wasm.networkmixin_verify_proof(this.__wbg_ptr, proof_memory.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const NetworkSecretFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_networksecret_free(ptr >>> 0, 1));
/**
*/
export class NetworkSecret {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(NetworkSecret.prototype);
        obj.__wbg_ptr = ptr;
        NetworkSecretFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        NetworkSecretFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_networksecret_free(ptr, 0);
    }
    /**
    * @returns {Memory}
    */
    to_secret() {
        const ret = wasm.networksecret_to_secret(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Memory}
    */
    to_proof() {
        const ret = wasm.networksecret_to_proof(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Memory}
    */
    to_value() {
        const ret = wasm.networksecret_to_value(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Ripemd160HasherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ripemd160hasher_free(ptr >>> 0, 1));
/**
*/
export class Ripemd160Hasher {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Ripemd160Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Ripemd160HasherFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Ripemd160HasherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ripemd160hasher_free(ptr, 0);
    }
    /**
    */
    constructor() {
        const ret = wasm.ripemd160hasher_new();
        this.__wbg_ptr = ret >>> 0;
        Ripemd160HasherFinalization;
        return this;
    }
    /**
    * @returns {Ripemd160Hasher}
    */
    clone() {
        const ret = wasm.ripemd160hasher_clone(this.__wbg_ptr);
        return Ripemd160Hasher.__wrap(ret);
    }
    /**
    * @param {Memory} data
    */
    update(data) {
        _assertClass(data, Memory);
        wasm.ripemd160hasher_update(this.__wbg_ptr, data.__wbg_ptr);
    }
    /**
    * @returns {Memory}
    */
    finalize() {
        const ret = wasm.ripemd160hasher_finalize(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Secp256k1SignatureAndRecoveryFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secp256k1signatureandrecovery_free(ptr >>> 0, 1));
/**
*/
export class Secp256k1SignatureAndRecovery {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Secp256k1SignatureAndRecovery.prototype);
        obj.__wbg_ptr = ptr;
        Secp256k1SignatureAndRecoveryFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Secp256k1SignatureAndRecoveryFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1signatureandrecovery_free(ptr, 0);
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.secp256k1signatureandrecovery_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Secp256k1SigningKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secp256k1signingkey_free(ptr >>> 0, 1));
/**
*/
export class Secp256k1SigningKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Secp256k1SigningKey.prototype);
        obj.__wbg_ptr = ptr;
        Secp256k1SigningKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Secp256k1SigningKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1signingkey_free(ptr, 0);
    }
    /**
    */
    constructor() {
        const ret = wasm.secp256k1signingkey_new();
        this.__wbg_ptr = ret >>> 0;
        Secp256k1SigningKeyFinalization;
        return this;
    }
    /**
    * @returns {Secp256k1SigningKey}
    */
    static random() {
        const ret = wasm.secp256k1signingkey_new();
        return Secp256k1SigningKey.__wrap(ret);
    }
    /**
    * @param {Memory} input
    * @returns {Secp256k1SigningKey}
    */
    static from_bytes(input) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(input, Memory);
            wasm.secp256k1signingkey_from_bytes(retptr, input.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Secp256k1SigningKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.secp256k1signingkey_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Secp256k1VerifyingKey}
    */
    verifying_key() {
        const ret = wasm.secp256k1signingkey_verifying_key(this.__wbg_ptr);
        return Secp256k1VerifyingKey.__wrap(ret);
    }
    /**
    * @param {Memory} hashed
    * @returns {Secp256k1SignatureAndRecovery}
    */
    sign_prehash_recoverable(hashed) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(hashed, Memory);
            wasm.secp256k1signingkey_sign_prehash_recoverable(retptr, this.__wbg_ptr, hashed.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Secp256k1SignatureAndRecovery.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}

const Secp256k1VerifyingKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secp256k1verifyingkey_free(ptr >>> 0, 1));
/**
*/
export class Secp256k1VerifyingKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Secp256k1VerifyingKey.prototype);
        obj.__wbg_ptr = ptr;
        Secp256k1VerifyingKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Secp256k1VerifyingKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secp256k1verifyingkey_free(ptr, 0);
    }
    /**
    * @param {Memory} input
    * @returns {Secp256k1VerifyingKey}
    */
    static from_sec1_bytes(input) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(input, Memory);
            wasm.secp256k1verifyingkey_from_sec1_bytes(retptr, input.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Secp256k1VerifyingKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} hashed
    * @param {Secp256k1SignatureAndRecovery} signature
    * @returns {Secp256k1VerifyingKey}
    */
    static recover_from_prehash(hashed, signature) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(hashed, Memory);
            _assertClass(signature, Secp256k1SignatureAndRecovery);
            wasm.secp256k1verifyingkey_recover_from_prehash(retptr, hashed.__wbg_ptr, signature.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Secp256k1VerifyingKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Memory}
    */
    to_sec1_compressed_bytes() {
        const ret = wasm.secp256k1verifyingkey_to_sec1_compressed_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {Memory}
    */
    to_sec1_uncompressed_bytes() {
        const ret = wasm.secp256k1verifyingkey_to_sec1_uncompressed_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const Sha1HasherFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sha1hasher_free(ptr >>> 0, 1));
/**
*/
export class Sha1Hasher {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Sha1Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Sha1HasherFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Sha1HasherFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sha1hasher_free(ptr, 0);
    }
    /**
    */
    constructor() {
        const ret = wasm.sha1hasher_new();
        this.__wbg_ptr = ret >>> 0;
        Sha1HasherFinalization;
        return this;
    }
    /**
    * @returns {Sha1Hasher}
    */
    clone() {
        const ret = wasm.sha1hasher_clone(this.__wbg_ptr);
        return Sha1Hasher.__wrap(ret);
    }
    /**
    * @param {Memory} data
    */
    update(data) {
        _assertClass(data, Memory);
        wasm.sha1hasher_update(this.__wbg_ptr, data.__wbg_ptr);
    }
    /**
    * @returns {Memory}
    */
    finalize() {
        const ret = wasm.sha1hasher_finalize(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const X25519PublicKeyFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_x25519publickey_free(ptr >>> 0, 1));
/**
*/
export class X25519PublicKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(X25519PublicKey.prototype);
        obj.__wbg_ptr = ptr;
        X25519PublicKeyFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        X25519PublicKeyFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_x25519publickey_free(ptr, 0);
    }
    /**
    * @param {Memory} bytes
    */
    constructor(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.x25519publickey_new(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            X25519PublicKeyFinalization;
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Memory} bytes
    * @returns {X25519PublicKey}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.x25519publickey_from_bytes(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return X25519PublicKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.x25519publickey_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
}

const X25519SharedSecretFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_x25519sharedsecret_free(ptr >>> 0, 1));
/**
*/
export class X25519SharedSecret {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(X25519SharedSecret.prototype);
        obj.__wbg_ptr = ptr;
        X25519SharedSecretFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        X25519SharedSecretFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_x25519sharedsecret_free(ptr, 0);
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.x25519sharedsecret_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @returns {boolean}
    */
    was_contributory() {
        const ret = wasm.x25519sharedsecret_was_contributory(this.__wbg_ptr);
        return ret !== 0;
    }
}

const X25519StaticSecretFinalization = true
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_x25519staticsecret_free(ptr >>> 0, 1));
/**
*/
export class X25519StaticSecret {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(X25519StaticSecret.prototype);
        obj.__wbg_ptr = ptr;
        X25519StaticSecretFinalization;
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        X25519StaticSecretFinalization;
        return ptr;
    }

    [Symbol.dispose]() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_x25519staticsecret_free(ptr, 0);
    }
    /**
    */
    constructor() {
        const ret = wasm.x25519staticsecret_random();
        this.__wbg_ptr = ret >>> 0;
        X25519StaticSecretFinalization;
        return this;
    }
    /**
    * @param {Memory} bytes
    * @returns {X25519StaticSecret}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bytes, Memory);
            wasm.x25519publickey_from_bytes(retptr, bytes.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return X25519StaticSecret.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Memory}
    */
    to_bytes() {
        const ret = wasm.x25519publickey_to_bytes(this.__wbg_ptr);
        return Memory.__wrap(ret);
    }
    /**
    * @param {X25519PublicKey} other
    * @returns {X25519SharedSecret}
    */
    diffie_hellman(other) {
        _assertClass(other, X25519PublicKey);
        const ret = wasm.x25519staticsecret_diffie_hellman(this.__wbg_ptr, other.__wbg_ptr);
        return X25519SharedSecret.__wrap(ret);
    }
    /**
    * @returns {X25519PublicKey}
    */
    to_public() {
        const ret = wasm.x25519staticsecret_to_public(this.__wbg_ptr);
        return X25519PublicKey.__wrap(ret);
    }
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_object_drop_ref = function(arg0) {
        takeObject(arg0);
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_error_new = function(arg0, arg1) {
        const ret = new Error(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'function';
        return ret;
    };
    imports.wbg.__wbg_newnoargs_76313bd6ff35d0f2 = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = getObject(arg0);
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbg_call_1084a111329e68ce = function() { return handleError(function (arg0, arg1) {
        const ret = getObject(arg0).call(getObject(arg1));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'string';
        return ret;
    };
    imports.wbg.__wbindgen_object_clone_ref = function(arg0) {
        const ret = getObject(arg0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_self_3093d5d1f7bcb682 = function() { return handleError(function () {
        const ret = self.self;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_window_3bcfc4d31bc012f8 = function() { return handleError(function () {
        const ret = window.window;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_globalThis_86b222e13bdf32ed = function() { return handleError(function () {
        const ret = globalThis.globalThis;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_global_e5a3fe56f8be9485 = function() { return handleError(function () {
        const ret = global.global;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = getObject(arg0) === undefined;
        return ret;
    };
    imports.wbg.__wbg_call_89af060b4e1523f2 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_buffer_b7b08af79b0b0974 = function(arg0) {
        const ret = getObject(arg0).buffer;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_8a2cb9ca96b27ec9 = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_new_ea1883e1e5e86686 = function(arg0) {
        const ret = new Uint8Array(getObject(arg0));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_set_d1e79e2388520f18 = function(arg0, arg1, arg2) {
        getObject(arg0).set(getObject(arg1), arg2 >>> 0);
    };
    imports.wbg.__wbg_newwithlength_ec548f448387c968 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_subarray_7c2e3576afe181d1 = function(arg0, arg1, arg2) {
        const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_crypto_1d1f22824a6a080c = function(arg0) {
        const ret = getObject(arg0).crypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_process_4a72847cc503995b = function(arg0) {
        const ret = getObject(arg0).process;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_versions_f686565e586dd935 = function(arg0) {
        const ret = getObject(arg0).versions;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_node_104a2ff8d6ea03a2 = function(arg0) {
        const ret = getObject(arg0).node;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_require_cca90b1a94a0255b = function() { return handleError(function () {
        const ret = module.require;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_msCrypto_eb05e62b530a1508 = function(arg0) {
        const ret = getObject(arg0).msCrypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_randomFillSync_5c9c955aa56b6049 = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).randomFillSync(takeObject(arg1));
    }, arguments) };
    imports.wbg.__wbg_getRandomValues_3aa56aa6edec874c = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).getRandomValues(getObject(arg1));
    }, arguments) };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;



    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined' && Object.getPrototypeOf(module) === Object.prototype)
    ({module} = module)
    else
    console.warn('using deprecated parameters for `initSync()`; pass a single object instead')

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined' && Object.getPrototypeOf(module_or_path) === Object.prototype)
    ({module_or_path} = module_or_path)
    else
    console.warn('using deprecated parameters for the initialization function; pass a single object instead')

    if (typeof module_or_path === 'undefined') {
        throw new Error();
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;

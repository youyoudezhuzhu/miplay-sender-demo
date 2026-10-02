/*
 * miplay_aes_trace.js -- instrument the MiPlay AES setup to capture the real key/IV.
 *
 * WHY: static analysis pinned the *static* member mapping (see
 * reports/MIPLAY_VERIFIED_FINDINGS_V7.md §2.3) but nothing observed so far
 * proves which AES context a *specific* 8899 session actually used. The prior
 * 'padok' oracle was unsound and its 137/137 result is retracted. This script
 * answers the question directly: log the key and IV at AES init time.
 *
 * TARGETS: `libmirror-jni.so` (symbols intact). Hook the AES init entry and the
 * MiPlay-side key selection so both can be correlated.
 *
 * USAGE (device must be root, frida-server running):
 *   frida -U -f com.milink.service -l miplay_aes_trace.js --no-pause
 * or attach to the running service:
 *   frida -U -n com.milink.service -l miplay_aes_trace.js
 *
 * OUTPUT: one JSON line per event on stdout, plus /data/local/tmp/miplay_aes_trace.jsonl
 */

'use strict';

const LIB = 'libmirror-jni.so';
const OUT = '/data/local/tmp/miplay_aes_trace.jsonl';

/* ---------------------------------------------------------------- helpers */
function hexdump(ptr, len) {
    try { return hexdump0(ptr, len); } catch (e) { return '<unreadable>'; }
}
function hexdump0(ptr, len) {
    if (ptr.isNull()) return '<null>';
    const bytes = new Uint8Array(ptr.readByteArray(len));
    return Array.from(bytes).map(b => ('0' + b.toString(16)).slice(-2)).join('');
}
function ascii(ptr, len) {
    try {
        if (ptr.isNull()) return '';
        const s = ptr.readUtf8String(len);
        return /^[\x20-\x7e]*$/.test(s) ? s : '';
    } catch (e) { return ''; }
}

let logFile = null;
function emit(ev) {
    ev.ts = Date.now();
    const line = JSON.stringify(ev);
    console.log(line);
    try {
        if (logFile === null) logFile = new File(OUT, 'a');
        logFile.write(line + '\n');
        logFile.flush();
    } catch (e) { /* logging is best-effort */ }
}

/* ------------------------------------------------- locate AES entry points */
function findExport(mod, names) {
    for (const n of names) {
        const p = mod.findExportByName(n);
        if (p) return { name: n, addr: p };
    }
    return null;
}

function hookAesInit() {
    const mod = Process.findModuleByName(LIB);
    if (!mod) { emit({ ev: 'error', msg: LIB + ' not loaded yet' }); return false; }

    // OpenSSL/BoringSSL-style and mbedTLS-style entry points, whichever exist.
    const candidates = [
        // BoringSSL / OpenSSL
        { names: ['AES_set_encrypt_key', 'AES_set_decrypt_key'], args: 'openssl_setkey' },
        { names: ['AES_cbc_encrypt'],                            args: 'openssl_cbc' },
        // mbedTLS
        { names: ['mbedtls_aes_setkey_enc', 'mbedtls_aes_setkey_dec'], args: 'mbedtls_setkey' },
        { names: ['mbedtls_aes_crypt_cbc'],                      args: 'mbedtls_cbc' },
        // generic
        { names: ['AES_init_ctx_iv', 'aes_init_ctx_iv'],         args: 'ctx_iv' },
    ];

    let hookedAny = false;
    for (const c of candidates) {
        const found = findExport(mod, c.names);
        if (!found) continue;
        hookedAny = true;

        Interceptor.attach(found.addr, {
            onEnter(args) {
                const kind = c.args;
                try {
                    if (kind === 'openssl_setkey') {
                        // (const AES_KEY *key, const void *userKey, int bits) or reversed
                        emit({
                            ev: 'aes_setkey', fn: found.name,
                            a0: args[0].toString(), a1: args[1].toString(), bits: args[2].toInt32(),
                            buf0: hexdump(args[0], 32), buf1: hexdump(args[1], 32),
                            bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .slice(0, 8).map(DebugSymbol.fromAddress).map(String),
                        });
                    } else if (kind === 'mbedtls_setkey') {
                        emit({
                            ev: 'mbedtls_setkey', fn: found.name,
                            ctx: args[0].toString(), key: hexdump(args[1], 16),
                            bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .slice(0, 8).map(DebugSymbol.fromAddress).map(String),
                        });
                    } else if (kind === 'openssl_cbc' || kind === 'mbedtls_cbc') {
                        emit({
                            ev: 'aes_cbc', fn: found.name,
                            in: args[0].toString(), len: args[2].toInt32(),
                            iv: hexdump(args[3], 16),
                            bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .slice(0, 8).map(DebugSymbol.fromAddress).map(String),
                        });
                    } else {
                        emit({
                            ev: 'aes_ctx_iv', fn: found.name,
                            ctx: args[0].toString(),
                            key: hexdump(args[1], 16), iv: hexdump(args[2], 16),
                            bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .slice(0, 8).map(DebugSymbol.fromAddress).map(String),
                        });
                    }
                } catch (e) {
                    emit({ ev: 'error', fn: found.name, msg: String(e) });
                }
            }
        });
        console.log('[+] hooked ' + found.name);
    }
    if (!hookedAny) {
        emit({ ev: 'error', msg: 'no AES entry points found in ' + LIB });
    }
    return hookedAny;
}

/* ------------------------------------------- hook MiPlay key-selection side */
function hookMiplayKeyPath() {
    const mod = Process.findModuleByName(LIB);
    if (!mod) return;

    // Mangled names carry the full signature, so match by substring.
    const exports = mod.enumerateExports();
    const wanted = [
        { sub: 'setLyraInfo',  ev: 'setLyraInfo'  },
        { sub: 'genAesKey',    ev: 'genAesKey'    },
        { sub: 'genAesIv',     ev: 'genAesIv'     },
        { sub: 'genAuthKey',   ev: 'genAuthKey'   },
        { sub: 'onSessionConnect', ev: 'onSessionConnect' },
        { sub: 'SafetyDataDeal', ev: 'SafetyDataDeal' },
        { sub: 'encryptData',  ev: 'encryptData'  },
        { sub: 'decryptData',  ev: 'decryptData'  },
    ];

    for (const w of wanted) {
        for (const e of exports) {
            if (e.name.indexOf(w.sub) === -1) continue;
            try {
                Interceptor.attach(e.address, {
                    onEnter(args) {
                        // Many of these take (this, std::string* , type). Log the
                        // first three pointers plus any ASCII at args[1]/args[2].
                        emit({
                            ev: w.ev, sym: e.name,
                            a0: args[0].toString(), a1: args[1].toString(),
                            a2: args[2].toString(), a3: args[3].toString(),
                            s1: ascii(args[1], 32), s2: ascii(args[2], 32),
                            bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .slice(0, 6).map(DebugSymbol.fromAddress).map(String),
                        });
                    }
                });
                console.log('[+] hooked ' + w.ev + ' (' + e.name + ')');
            } catch (err) { /* ignore individual failures */ }
        }
    }
}

/* --------------------------------------------------------------- bootstrap */
setTimeout(function () {
    console.log('[*] miplay_aes_trace starting');
    hookAesInit();
    hookMiplayKeyPath();
    // The service may load the library lazily; retry a few times.
    let tries = 0;
    const timer = setInterval(function () {
        tries++;
        if (Process.findModuleByName(LIB) && tries < 20) {
            hookAesInit();
        }
        if (tries >= 20) { clearInterval(timer); }
    }, 2000);
}, 0);

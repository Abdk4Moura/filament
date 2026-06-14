/* tslint:disable */
/* eslint-disable */

/**
 * A live SPAKE2 session for the browser. Owns the secret scalar; consumed
 * by `finish`.
 */
export class PakeSession {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Consume the peer's element; derive K (held internally). Returns true
     * on success. After this, `confirm_mac`/`secret` are available.
     */
    finish(peer_msg: Uint8Array): boolean;
    /**
     * The 33-byte outbound SPAKE2 element to relay to the peer.
     */
    message(): Uint8Array;
    /**
     * Begin symmetric SPAKE2 with OsRng (crypto.getRandomValues).
     */
    constructor(password: Uint8Array, nameplate: Uint8Array);
    /**
     * §4 confirmation MAC THIS side sends. Handles fingerprint sorting +
     * symmetric role derivation so the browser can't get it wrong.
     */
    ourConfirm(my_fp: string, their_fp: string, caps: string): Uint8Array | undefined;
    /**
     * §5.1 derived 64-hex pinned secret. None until `finish` succeeds.
     */
    secret(): string | undefined;
    /**
     * Verify the peer's confirmation MAC under our K. true == confirmed.
     */
    verifyPeerConfirm(my_fp: string, their_fp: string, caps: string, received: Uint8Array): boolean;
}

/**
 * Canonicalize a JS string[] capability set (for confirm-MAC parity).
 */
export function canonicalCaps(caps: any[]): string;

/**
 * Constant-time MAC comparison exposed for the browser verify step.
 */
export function ctEq(a: Uint8Array, b: Uint8Array): boolean;

/**
 * Normalize a spoken code (mirrors backend `_norm_code`).
 */
export function normCode(raw: string): string;

/**
 * Split a user-CHOSEN code into [password, nameplate_or_empty_string]. The
 * trailing group is the nameplate ONLY if it is 3-5 ASCII digits.
 */
export function splitChosenCode(normalized: string): any[];

/**
 * Split a normalized code into [nameplate, password].
 */
export function splitCode(normalized: string): any[];

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_pakesession_free: (a: number, b: number) => void;
    readonly canonicalCaps: (a: number, b: number) => [number, number];
    readonly ctEq: (a: number, b: number, c: number, d: number) => number;
    readonly normCode: (a: number, b: number) => [number, number];
    readonly pakesession_finish: (a: number, b: number, c: number) => number;
    readonly pakesession_message: (a: number) => [number, number];
    readonly pakesession_new: (a: number, b: number, c: number, d: number) => number;
    readonly pakesession_ourConfirm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly pakesession_secret: (a: number) => [number, number];
    readonly pakesession_verifyPeerConfirm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
    readonly splitChosenCode: (a: number, b: number) => [number, number];
    readonly splitCode: (a: number, b: number) => [number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
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

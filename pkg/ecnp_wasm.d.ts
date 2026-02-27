/* tslint:disable */
/* eslint-disable */

/**
 * Decoded ECNP frame.
 */
export class EcnpFrame {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Get the payload as a UTF-8 string (returns empty if invalid UTF-8).
     */
    payloadString(): string;
    /**
     * Get the message type byte.
     */
    readonly msg_type: number;
    /**
     * Get the payload as a byte array.
     */
    readonly payload: Uint8Array;
}

/**
 * ECNP message types.
 */
export enum MessageType {
    Handshake = 1,
    Data = 2,
    Control = 3,
    Heartbeat = 4,
    Error = 5,
    Auth = 6,
    Telemetry = 7,
    PolicyUpdate = 8,
}

/**
 * Get bridge metadata as a JSON string.
 */
export function ecnpBridgeInfo(): string;

/**
 * Decode an ECNP v1.1 binary frame.
 *
 * @param data - Raw frame bytes
 * @returns Decoded EcnpFrame with msg_type and payload
 */
export function ecnpDecode(data: Uint8Array): EcnpFrame;

/**
 * Encode a payload into an ECNP v1.1 binary frame.
 *
 * @param msg_type - Message type (0x01-0x08)
 * @param payload  - Raw payload bytes
 * @returns Encoded ECNP frame bytes
 */
export function ecnpEncode(msg_type: number, payload: Uint8Array): Uint8Array;

/**
 * Encode a string payload into an ECNP frame.
 *
 * Convenience wrapper that encodes a UTF-8 string.
 */
export function ecnpEncodeString(msg_type: number, text: string): Uint8Array;

/**
 * Encode→Decode roundtrip test (self-test callable from JS).
 *
 * @returns true if roundtrip succeeds
 */
export function ecnpSelfTest(): boolean;

/**
 * Validate an ECNP frame without extracting the payload.
 *
 * @param data - Raw frame bytes
 * @returns true if the frame is valid
 */
export function ecnpValidate(data: Uint8Array): boolean;

/**
 * Get the ECNP protocol version string.
 */
export function ecnpVersion(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_ecnpframe_free: (a: number, b: number) => void;
    readonly ecnpBridgeInfo: () => [number, number];
    readonly ecnpDecode: (a: number, b: number) => [number, number, number];
    readonly ecnpEncode: (a: number, b: number, c: number) => [number, number, number, number];
    readonly ecnpEncodeString: (a: number, b: number, c: number) => [number, number, number, number];
    readonly ecnpSelfTest: () => number;
    readonly ecnpValidate: (a: number, b: number) => number;
    readonly ecnpVersion: () => [number, number];
    readonly ecnpframe_msg_type: (a: number) => number;
    readonly ecnpframe_payload: (a: number) => [number, number];
    readonly ecnpframe_payloadString: (a: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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

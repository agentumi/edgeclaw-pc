# WASM SDK Reference

> EdgeClaw V3.0 — WebAssembly Protocol SDK

## Overview

The `ecnp-wasm` package provides the ECNP v1.1 binary protocol codec compiled
to WebAssembly, enabling browsers and Node.js applications to encode/decode
EdgeClaw Network Protocol frames.

## Installation

```bash
npm install ecnp-wasm
```

Or load from CDN:

```html
<script type="module">
  import init, { ecnpEncode, ecnpDecode } from './ecnp_wasm.js';
  await init();
</script>
```

## Quick Start

```javascript
import init, {
  ecnpEncode,
  ecnpDecode,
  ecnpValidate,
  ecnpVersion,
  ecnpBridgeInfo,
  ecnpSelfTest,
  MessageType
} from 'ecnp-wasm';

// Initialize WASM module
await init();

// Encode a Heartbeat message
const payload = new TextEncoder().encode('ping');
const frame = ecnpEncode(MessageType.Heartbeat, payload);
console.log('Frame:', new Uint8Array(frame));

// Decode the frame
const decoded = ecnpDecode(frame);
console.log('Type:', decoded.msg_type);       // 4 (Heartbeat)
console.log('Payload:', decoded.payloadString()); // "ping"

// Validate without decoding
console.log('Valid:', ecnpValidate(frame)); // true

// Self-test
console.log('Self-test:', ecnpSelfTest()); // true
```

## API Reference

### Functions

#### `ecnpEncode(msgType: number, payload: Uint8Array): Uint8Array`

Encode a payload into an ECNP v1.1 binary frame.

| Parameter | Type | Description |
|-----------|------|-------------|
| `msgType` | `number` | Message type (0x01-0x08) |
| `payload` | `Uint8Array` | Raw payload bytes |
| **Returns** | `Uint8Array` | Encoded ECNP frame |

**Throws**: `Error` if message type is invalid or payload exceeds 1MB.

#### `ecnpDecode(data: Uint8Array): EcnpFrame`

Decode an ECNP v1.1 binary frame.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `Uint8Array` | Raw frame bytes |
| **Returns** | `EcnpFrame` | Decoded frame object |

**Throws**: `Error` if frame is invalid.

#### `ecnpValidate(data: Uint8Array): boolean`

Check if a byte array is a valid ECNP frame.

#### `ecnpEncodeString(msgType: number, text: string): Uint8Array`

Convenience function to encode a UTF-8 string payload.

#### `ecnpVersion(): string`

Returns `"ECNP/1.1"`.

#### `ecnpBridgeInfo(): string`

Returns JSON metadata about the WASM bridge:

```json
{
  "protocol": "ECNP/1.1",
  "bridge_version": "1.0.0",
  "target": "wasm32-unknown-unknown",
  "message_types": ["Handshake", "Data", "Control", "Heartbeat",
                     "Error", "Auth", "Telemetry", "PolicyUpdate"]
}
```

#### `ecnpSelfTest(): boolean`

Runs an internal encode→decode roundtrip test.

### Types

#### `EcnpFrame`

| Property | Type | Description |
|----------|------|-------------|
| `msg_type` | `number` | Message type byte |
| `payload` | `Uint8Array` | Decoded payload |
| `payloadString()` | `string` | Payload as UTF-8 |

#### `MessageType` (enum)

| Name | Value | Description |
|------|-------|-------------|
| `Handshake` | `0x01` | Connection handshake |
| `Data` | `0x02` | Data transfer |
| `Control` | `0x03` | Control command |
| `Heartbeat` | `0x04` | Keep-alive |
| `Error` | `0x05` | Error response |
| `Auth` | `0x06` | Authentication |
| `Telemetry` | `0x07` | Metrics/telemetry |
| `PolicyUpdate` | `0x08` | Policy change |

## Frame Format

```
+--------+--------+--------+--------+--------+--------+--...--+
| Version| MsgType|       Length (4 bytes BE)        | Payload |
+--------+--------+--------+--------+--------+--------+--...--+
   1B       1B                 4B                     0-1MB
```

- **Version**: Always `0x01` (ECNP v1.1)
- **MsgType**: `0x01`-`0x08`
- **Length**: 4-byte big-endian payload length
- **Payload**: Up to 1MB

## Browser Usage

```html
<!DOCTYPE html>
<html>
<head><title>ECNP Demo</title></head>
<body>
<script type="module">
  import init, { ecnpEncode, ecnpDecode, MessageType } from './ecnp_wasm.js';

  async function main() {
    await init();

    // Create a heartbeat frame
    const payload = new TextEncoder().encode(JSON.stringify({
      uptime: 3600,
      peers: 5
    }));
    const frame = ecnpEncode(MessageType.Heartbeat, payload);

    // Send via WebSocket
    const ws = new WebSocket('wss://agent.example.com:9445');
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => ws.send(frame);
    ws.onmessage = (e) => {
      const decoded = ecnpDecode(new Uint8Array(e.data));
      console.log('Received:', decoded.msg_type, decoded.payloadString());
    };
  }

  main();
</script>
</body>
</html>
```

## Node.js Usage

```javascript
const { ecnpEncode, ecnpDecode } = require('ecnp-wasm');
const net = require('net');

const frame = ecnpEncode(0x02, Buffer.from('hello'));
const client = net.createConnection(8443, 'localhost', () => {
  client.write(Buffer.from(frame));
});
```

## Building from Source

```bash
cd wasm-pkg
wasm-pack build --target web --out-dir ../pkg

# Output:
# pkg/package.json      - npm package manifest
# pkg/ecnp_wasm.js      - JavaScript glue code
# pkg/ecnp_wasm.d.ts     - TypeScript type definitions
# pkg/ecnp_wasm_bg.wasm  - WASM binary (~63KB)
```

## Package Size

| File | Size |
|------|------|
| `ecnp_wasm_bg.wasm` | ~63 KB |
| `ecnp_wasm.js` | ~12 KB |
| `ecnp_wasm.d.ts` | ~4 KB |
| **Total** | **< 80 KB** |

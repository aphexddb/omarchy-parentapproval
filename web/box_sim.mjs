// Decrypt a SealAsk blob the way app.js openSealed does.
// Usage: node box_sim.mjs <blob_b64url> <ed25519_secret_b64url>
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const nacl = require(join(dirname(fileURLToPath(import.meta.url)), "nacl.min.js"));

function b64urlToBytes(s) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function ed25519SeedToX25519(sk) {
  const seed = sk.length >= 32 ? sk.subarray(0, 32) : sk;
  const h = nacl.hash(seed);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return h.subarray(0, 32);
}

function openSealed(blobB64, sk) {
  const raw = b64urlToBytes(blobB64);
  if (raw.length < 32 + 24 + 16) throw new Error("bad sealed ask");
  const eph = raw.subarray(0, 32);
  const nonce = raw.subarray(32, 56);
  const ct = raw.subarray(56);
  const plain = nacl.box.open(ct, nonce, eph, ed25519SeedToX25519(sk));
  if (!plain) throw new Error("could not decrypt ask");
  return JSON.parse(new TextDecoder().decode(plain));
}

const blob = process.argv[2];
const secret = process.argv[3];
if (!blob || !secret) {
  console.error("usage: node box_sim.mjs <blob> <secret>");
  process.exit(2);
}
process.stdout.write(JSON.stringify(openSealed(blob, b64urlToBytes(secret))));

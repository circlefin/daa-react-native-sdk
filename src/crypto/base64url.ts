/**
 * Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Unpadded Base64URL (RFC 4648 §5) codec. Implemented without Buffer/atob/btoa
// so it behaves identically on React Native, Node, and browsers.

const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

// Values are always masked to 0..63, so the lookup is total.
const enc = (v: number): string => B64URL_CHARS[v]!

// Decode table, built once at module load rather than per fromBase64Url() call.
const B64URL_LOOKUP: Record<string, number> = (() => {
  const table: Record<string, number> = {}
  for (let i = 0; i < B64URL_CHARS.length; i++) {
    table[B64URL_CHARS[i]!] = i
  }
  return table
})()

/** Encode bytes as unpadded Base64URL. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = ''
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
    out += enc((n >>> 18) & 63) + enc((n >>> 12) & 63) + enc((n >>> 6) & 63) + enc(n & 63)
  }
  const rem = bytes.length - i
  if (rem === 1) {
    const n = bytes[i]! << 16
    out += enc((n >>> 18) & 63) + enc((n >>> 12) & 63)
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8)
    out += enc((n >>> 18) & 63) + enc((n >>> 12) & 63) + enc((n >>> 6) & 63)
  }
  return out
}

/**
 * Decode unpadded Base64URL back to bytes. Strict: rejects invalid characters,
 * an impossible length (`len % 4 === 1`), and non-canonical encodings whose
 * trailing bits are non-zero. Strictness matters because this decodes SPKI and
 * ES256 signatures, where malleable inputs must not silently pass.
 */
export function fromBase64Url(input: string): Uint8Array {
  const len = input.length
  if (len % 4 === 1) {
    throw new Error('DAA: invalid Base64URL length')
  }
  const outLen = Math.floor((len * 6) / 8)
  const out = new Uint8Array(outLen)
  let bits = 0
  let acc = 0
  let p = 0
  for (let i = 0; i < len; i++) {
    const v = B64URL_LOOKUP[input[i]!]
    if (v === undefined) {
      throw new Error('DAA: invalid Base64URL input')
    }
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[p++] = (acc >>> bits) & 0xff
    }
  }
  // Leftover bits of a canonical encoding must be zero padding.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) {
    throw new Error('DAA: non-canonical Base64URL (non-zero trailing bits)')
  }
  return out
}

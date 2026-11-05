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

import { bytesToHex, hexToBytes } from './authKeyWireFixture'

describe('hexToBytes', () => {
  it('decodes lower-case hex and round-trips through bytesToHex', () => {
    expect(Array.from(hexToBytes('00ff10'))).toEqual([0x00, 0xff, 0x10])
    expect(bytesToHex(hexToBytes('0a1b2c'))).toBe('0a1b2c')
  })

  it('rejects a non-hex character in the second nibble', () => {
    // `Number.parseInt` stops at the first invalid character rather than
    // failing, so `Number.parseInt('1z', 16)` is 1. A per-byte NaN check would
    // decode this as 0x01 and report nothing.
    expect(Number.isNaN(Number.parseInt('1z', 16))).toBe(false)
    expect(() => hexToBytes('1z')).toThrow(/non-hex character/)
  })

  it('rejects a non-hex character in the first nibble', () => {
    expect(() => hexToBytes('z1')).toThrow(/non-hex character/)
  })

  it('rejects upper-case hex, which the fixture never uses', () => {
    expect(() => hexToBytes('AB')).toThrow(/non-hex character/)
  })

  it('rejects an odd-length string before decoding', () => {
    expect(() => hexToBytes('abc')).toThrow(/odd length/)
  })

  it('decodes the empty string', () => {
    expect(Array.from(hexToBytes(''))).toEqual([])
  })
})

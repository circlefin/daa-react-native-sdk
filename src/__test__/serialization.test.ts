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

import { serializeBody, serializeEmptyBody } from '../crypto/serialization'

describe('serializeBody', () => {
  it('produces exact UTF-8 bytes of the JSON encoding', () => {
    const bytes = serializeBody({ a: 1, b: 'x' })
    expect(new TextDecoder().decode(bytes)).toBe('{"a":1,"b":"x"}')
  })

  it('is deterministic for the same input', () => {
    const a = serializeBody({ idempotencyKey: 'k', amount: '1.00' })
    const b = serializeBody({ idempotencyKey: 'k', amount: '1.00' })
    expect(Array.from(a)).toEqual(Array.from(b))
  })

  it('preserves author key order (serialize once, do not canonicalize)', () => {
    const bytes = serializeBody({ b: 1, a: 2 })
    expect(new TextDecoder().decode(bytes)).toBe('{"b":1,"a":2}')
  })

  it('throws when the value is not JSON-serializable', () => {
    expect(() => serializeBody(undefined)).toThrow(/not JSON-serializable/)
  })

  it('encodes a body-less request as the empty byte array', () => {
    expect(serializeEmptyBody().length).toBe(0)
  })
})

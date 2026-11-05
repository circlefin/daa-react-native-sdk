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

import {
  asObject,
  MalformedPayloadError,
  optionalNonNegativeInteger,
  optionalNonNegativeNumber,
  optionalObject,
  optionalString,
  requiredNonNegativeInteger,
  requiredString,
  unrecognized,
} from '../wire/payload'

describe('payload primitives', () => {
  it('rejects non-object payloads', () => {
    for (const value of [null, [], 'text', 1]) {
      expect(() => asObject(value, 'payload')).toThrow(MalformedPayloadError)
    }
  })

  it('reads optional strings and treats omitted or null fields as absent', () => {
    expect(optionalString({}, 'value')).toBeNull()
    expect(optionalString({ value: null }, 'value')).toBeNull()
    expect(optionalString({ value: 'ok' }, 'value')).toBe('ok')
    expect(() => optionalString({ value: 1 }, 'value', 'label')).toThrow('label')
  })

  it('reads optional objects and treats omitted or null fields as absent', () => {
    expect(optionalObject({}, 'value')).toBeNull()
    expect(optionalObject({ value: null }, 'value')).toBeNull()
    expect(optionalObject({ value: { nested: true } }, 'value')).toEqual({ nested: true })
    expect(() => optionalObject({ value: [] }, 'value')).toThrow(MalformedPayloadError)
    expect(() => optionalObject({ value: 'nope' }, 'value')).toThrow('value')
  })

  it('requires a string field', () => {
    expect(requiredString({ value: 'ok' }, 'value')).toBe('ok')
    expect(() => requiredString({}, 'value')).toThrow(MalformedPayloadError)
    expect(() => requiredString({ value: null }, 'value')).toThrow(MalformedPayloadError)
  })

  it('creates a frozen unrecognized arm that preserves the raw value', () => {
    const value = unrecognized('__proto__')
    expect(value).toEqual({ kind: 'unrecognized', rawValue: '__proto__' })
    expect(Object.isFrozen(value)).toBe(true)
  })

  it('requires a non-negative integer field, sent as a JSON number', () => {
    expect(requiredNonNegativeInteger({ value: 0 }, 'value')).toBe(0)
    expect(requiredNonNegativeInteger({ value: 5000000 }, 'value')).toBe(5000000)
    expect(() => requiredNonNegativeInteger({}, 'value')).toThrow(MalformedPayloadError)
    expect(() => requiredNonNegativeInteger({ value: null }, 'value')).toThrow(
      MalformedPayloadError,
    )
    expect(() => requiredNonNegativeInteger({ value: -1 }, 'value')).toThrow(MalformedPayloadError)
    expect(() => requiredNonNegativeInteger({ value: 1.5 }, 'value')).toThrow(MalformedPayloadError)
    expect(() => requiredNonNegativeInteger({ value: '5' }, 'value', 'label')).toThrow('label')
  })

  it('reads an optional non-negative integer field and treats omitted or null as absent', () => {
    expect(optionalNonNegativeInteger({}, 'value')).toBeNull()
    expect(optionalNonNegativeInteger({ value: null }, 'value')).toBeNull()
    expect(optionalNonNegativeInteger({ value: 7 }, 'value')).toBe(7)
    expect(() => optionalNonNegativeInteger({ value: -1 }, 'value')).toThrow(MalformedPayloadError)
  })

  it('reads an optional non-negative decimal field and treats omitted or null as absent', () => {
    expect(optionalNonNegativeNumber({}, 'value')).toBeNull()
    expect(optionalNonNegativeNumber({ value: null }, 'value')).toBeNull()
    expect(optionalNonNegativeNumber({ value: 24.69 }, 'value')).toBe(24.69)
    expect(optionalNonNegativeNumber({ value: 0 }, 'value')).toBe(0)
    expect(() => optionalNonNegativeNumber({ value: -0.01 }, 'value')).toThrow(
      MalformedPayloadError,
    )
    expect(() => optionalNonNegativeNumber({ value: '1' }, 'value', 'label')).toThrow('label')
  })
})

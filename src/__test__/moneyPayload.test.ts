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

import { inspect } from 'node:util'
import { optionalMoney, requiredMoney, toMoney } from '../wire/moneyPayload'
import { MalformedPayloadError } from '../wire/payload'

describe('money payload primitives', () => {
  it('preserves the exact decimal string and currency', () => {
    const money = toMoney({ amount: '12345678901234567890.00100', currency: 'USD' }, 'amount')

    expect(money.amount).toBe('12345678901234567890.00100')
    expect(money.currency).toBe('USD')
  })

  it('rejects absent, malformed, and JSON-number amounts with the caller label', () => {
    for (const value of [
      null,
      {},
      { amount: 1, currency: 'USD' },
      { amount: 'nope', currency: 'USD' },
    ]) {
      expect(() => toMoney(value, 'fee')).toThrow(MalformedPayloadError)
      try {
        toMoney(value, 'fee')
      } catch (error) {
        expect((error as MalformedPayloadError).fieldName).toMatch(/^fee(?:\.amount)?$/)
      }
    }
  })

  it('distinguishes required money from an absent optional field', () => {
    expect(optionalMoney({}, 'fee')).toBeNull()
    expect(optionalMoney({ fee: null }, 'fee')).toBeNull()
    expect(requiredMoney({ amount: { amount: '1.00', currency: 'EUR' } }, 'amount').amount).toBe(
      '1.00',
    )
    expect(() => requiredMoney({}, 'amount')).toThrow(MalformedPayloadError)
  })

  it('inherits Money redaction rather than exposing the amount in default renderings', () => {
    const validMoney = toMoney({ amount: '98765.4321', currency: 'USD' }, 'amount')

    for (const rendered of [JSON.stringify(validMoney), inspect(validMoney), String(validMoney)]) {
      expect(rendered).not.toContain('98765.4321')
    }
  })
})

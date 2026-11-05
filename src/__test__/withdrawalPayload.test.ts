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

import { MalformedPayloadError } from '../wire/payload'
import { toWithdrawalDetail } from '../wire/withdrawalPayload'

const COMPLETE = {
  id: 'a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd',
  sourceAccountId: '1000662322',
  destination: { type: 'wire', id: '0db1c81a-d36d-4777-8774-9682d96d82c8', name: 'Bank' },
  amount: { amount: '10.00', currency: 'USD' },
  status: 'complete',
  createDate: '2026-01-01T00:00:00Z',
}

function decode(extra: Record<string, unknown> = {}) {
  return toWithdrawalDetail({ ...COMPLETE, ...extra })
}

describe('withdrawal detail payload', () => {
  it('decodes the guaranteed core and defaults every absent enrichment', () => {
    const withdrawal = decode()

    expect(withdrawal.id).toBe(COMPLETE.id)
    expect(withdrawal.sourceAccountId).toBe('1000662322')
    expect(withdrawal.destination).toEqual({
      type: { kind: 'wire' },
      id: '0db1c81a-d36d-4777-8774-9682d96d82c8',
      name: 'Bank',
    })
    expect(withdrawal.amount.amount).toBe('10.00')
    expect(withdrawal.status).toEqual({ kind: 'complete' })
    expect(withdrawal.toAmount).toBeNull()
    expect(withdrawal.fees).toBeNull()
    expect(withdrawal.errorCode).toBeNull()
    expect(withdrawal.adjustments).toBeNull()
    expect(withdrawal.returnObject).toBeNull()
    expect(withdrawal.subAccountSweeps).toEqual([])
    expect(withdrawal.policyEvaluation).toBeNull()
    expect(withdrawal.updateDate).toBeNull()
  })

  it('decodes every enrichment shape', () => {
    const withdrawal = decode({
      toAmount: { amount: '9.50', currency: 'EUR' },
      fees: { amount: '0.50', currency: 'USD' },
      trackingRef: 'TRK-1',
      errorCode: 'transaction_returned',
      externalRef: 'IMAD-9',
      riskEvaluation: { decision: 'denied', reason: 'risk-rule' },
      adjustments: {
        fxCredit: { amount: '0.20', currency: 'USD' },
        fxDebit: { amount: '0.10', currency: 'USD' },
      },
      return: {
        id: 'return-id',
        payoutId: COMPLETE.id,
        amount: { amount: '8.50', currency: 'USD' },
        fees: { amount: '0.25', currency: 'USD' },
        reason: 'bank-return',
        status: 'complete',
        createDate: '2026-01-02T00:00:00Z',
        updateDate: '2026-01-03T00:00:00Z',
      },
      customerExternalRef: 'customer-ref-123',
      burnAll: true,
      subAccountSweeps: [
        {
          subAccountId: 'sub-1',
          amount: { amount: '4.00', currency: 'USD' },
          status: 'skipped',
        },
      ],
      updateDate: '2026-01-01T00:05:00Z',
      policyEvaluation: { status: 'approved' },
    })

    expect(withdrawal.toAmount?.amount).toBe('9.50')
    expect(withdrawal.fees?.amount).toBe('0.50')
    expect(withdrawal.errorCode).toEqual({ kind: 'transaction_returned' })
    expect(withdrawal.adjustments?.fxCredit?.amount).toBe('0.20')
    expect(withdrawal.returnObject?.amount?.amount).toBe('8.50')
    expect(withdrawal.subAccountSweeps[0]?.status).toEqual({ kind: 'skipped' })
    expect(withdrawal.policyEvaluation).toEqual({ status: 'approved' })
  })

  it('keeps closed sets forward-compatible and hostile object keys unrecognized', () => {
    for (const raw of ['settling', 'constructor', 'toString', '__proto__']) {
      expect(decode({ status: raw }).status).toEqual({ kind: 'unrecognized', rawValue: raw })
    }
    expect(decode({ errorCode: 'new_failure' }).errorCode).toEqual({
      kind: 'unrecognized',
      rawValue: 'new_failure',
    })
    expect(decode({ destination: { type: 'sepa', id: 'bank-id' } }).destination.type).toEqual({
      kind: 'unrecognized',
      rawValue: 'sepa',
    })
  })

  it('keeps nested return and sweep statuses forward-compatible', () => {
    const withdrawal = decode({
      return: { status: 'reversing' },
      subAccountSweeps: [{ status: 'queued' }],
    })

    expect(withdrawal.returnObject?.status).toEqual({
      kind: 'unrecognized',
      rawValue: 'reversing',
    })
    expect(withdrawal.subAccountSweeps[0]?.status).toEqual({
      kind: 'unrecognized',
      rawValue: 'queued',
    })
  })

  it('rejects missing core fields and malformed enrichment', () => {
    for (const name of ['id', 'sourceAccountId', 'destination', 'amount', 'status', 'createDate']) {
      const payload = { ...COMPLETE } as Record<string, unknown>
      delete payload[name]
      expect(() => toWithdrawalDetail(payload)).toThrow(MalformedPayloadError)
    }
    expect(() => decode({ amount: { amount: 10, currency: 'USD' } })).toThrow(MalformedPayloadError)
    expect(() => decode({ toAmount: { amount: 'not-a-number', currency: 'USD' } })).toThrow(
      MalformedPayloadError,
    )
    expect(() => decode({ burnAll: 'true' })).toThrow(MalformedPayloadError)
    expect(() => decode({ subAccountSweeps: {} })).toThrow(MalformedPayloadError)
    expect(() => decode({ policyEvaluation: { status: null } })).toThrow(MalformedPayloadError)
  })

  it('freezes the aggregate and nested collections', () => {
    const withdrawal = decode({ subAccountSweeps: [{ subAccountId: 'sub-1' }] })
    expect(Object.isFrozen(withdrawal)).toBe(true)
    expect(Object.isFrozen(withdrawal.destination)).toBe(true)
    expect(Object.isFrozen(withdrawal.subAccountSweeps)).toBe(true)
    expect(Object.isFrozen(withdrawal.subAccountSweeps[0])).toBe(true)
  })
})

describe('withdrawal detail redaction', () => {
  const secrets = [
    '123456.789',
    '98.50',
    '0.75',
    '0.20',
    '0.10',
    '87.25',
    '0.25',
    '4.00',
    'IMAD-SECRET',
    'CUSTOMER-SECRET',
  ]

  function enriched() {
    return decode({
      amount: { amount: secrets[0], currency: 'USD' },
      toAmount: { amount: secrets[1], currency: 'EUR' },
      fees: { amount: secrets[2], currency: 'USD' },
      externalRef: secrets[8],
      customerExternalRef: secrets[9],
      adjustments: {
        fxCredit: { amount: secrets[3], currency: 'USD' },
        fxDebit: { amount: secrets[4], currency: 'USD' },
      },
      return: {
        amount: { amount: secrets[5], currency: 'USD' },
        fees: { amount: secrets[6], currency: 'USD' },
      },
      subAccountSweeps: [{ amount: { amount: secrets[7], currency: 'USD' } }],
    })
  }

  function expectRedacted(rendered: string): void {
    for (const secret of secrets) {
      expect(rendered).not.toContain(secret)
    }
  }

  it('redacts JSON.stringify and toString', () => {
    const withdrawal = enriched()
    expectRedacted(JSON.stringify(withdrawal))
    expectRedacted(withdrawal.toString())
  })

  it('redacts Node inspection at default and unlimited depth', () => {
    const withdrawal = enriched()
    expectRedacted(inspect(withdrawal))
    expectRedacted(inspect(withdrawal, { depth: null }))
  })

  it('keeps sensitive fields out of enumeration, spread, and own keys', () => {
    const withdrawal = enriched()
    const ownKeys = Object.keys(withdrawal)
    for (const key of [
      'amount',
      'toAmount',
      'fees',
      'externalRef',
      'adjustments',
      'returnObject',
      'customerExternalRef',
      'subAccountSweeps',
    ]) {
      expect(ownKeys).not.toContain(key)
    }
    expectRedacted(JSON.stringify({ ...withdrawal }))
    const enumerated: Record<string, unknown> = {}
    for (const key in withdrawal) {
      enumerated[key] = withdrawal[key as keyof typeof withdrawal]
    }
    expectRedacted(JSON.stringify(enumerated))
  })

  it('still exposes exact values through explicit accessors', () => {
    const withdrawal = enriched()
    expect(withdrawal.amount.amount).toBe(secrets[0])
    expect(withdrawal.toAmount?.amount).toBe(secrets[1])
    expect(withdrawal.externalRef).toBe(secrets[8])
    expect(withdrawal.customerExternalRef).toBe(secrets[9])
  })
})

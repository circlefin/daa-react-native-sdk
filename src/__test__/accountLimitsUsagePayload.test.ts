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
import { AccountLimitsUsage } from '../models/AccountLimitsUsage'
import { toAccountLimitsUsage } from '../wire/accountLimitsUsagePayload'
import { MalformedPayloadError } from '../wire/payload'

/**
 * Decoding tests for the account limits/usage model. These go through the
 * real parse and mapping rather than constructing a payload object directly —
 * the wire spellings, the number handling, and the required/optional line are
 * the things under test. Mirrors `depositPayload.test.ts`.
 *
 * The public API reference
 * (https://developers.circle.com/api-reference/digital-asset-accounts/all/list-account-limits-usage)
 * is the source of truth these fixtures follow.
 */

const ACCOUNT_ID = '1000662322'

/** A transaction-limit item: window, currentAggregate, and usagePercent all absent. */
const TRANSACTION_ITEM =
  '{"operation":"withdrawal","assetType":"fiat","comparisonType":"transaction",' +
  '"unit":"usd_cents","effectiveThreshold":5000000}'

/** A count-based transaction-limit item, for the count unit. */
const COUNT_ITEM =
  '{"operation":"send_count","assetType":"crypto","comparisonType":"transaction",' +
  '"unit":"count","effectiveThreshold":10}'

/** An aggregation-limit item: every field the public reference documents. */
const AGGREGATION_ITEM =
  '{"operation":"send","assetType":"crypto","comparisonType":"aggregation","window":"PT24H",' +
  '"unit":"usd_cents","effectiveThreshold":1000000,"currentAggregate":1234567,"usagePercent":24.69}'

const REQUIRED =
  `"type":"limitsUsage","accountId":"${ACCOUNT_ID}","currency":"USD",` +
  '"watermark":"2026-05-12T10:29:58.000Z"'

function decode(body: string): AccountLimitsUsage {
  return toAccountLimitsUsage(JSON.parse(body) as unknown)
}

function decodeWithItems(items: string): AccountLimitsUsage {
  return decode(`{${REQUIRED},"items":[${items}]}`)
}

describe('required and optional fields', () => {
  it('rejects a response missing any guaranteed top-level field', () => {
    const complete: Record<string, string> = {
      type: '"limitsUsage"',
      accountId: `"${ACCOUNT_ID}"`,
      currency: '"USD"',
      watermark: '"2026-05-12T10:29:58.000Z"',
      items: `[${TRANSACTION_ITEM}]`,
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    // Sanity: the complete body decodes, or every assertion below is vacuous.
    expect(decode(body(complete)).accountId).toBe(ACCOUNT_ID)

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decode(body(partial))).toThrow(MalformedPayloadError)
    }

    expect(() => decode('{}')).toThrow(MalformedPayloadError)
    expect(() => toAccountLimitsUsage(null)).toThrow(MalformedPayloadError)
    expect(() => toAccountLimitsUsage([])).toThrow(MalformedPayloadError)
  })

  it('rejects an items value that is not an array', () => {
    expect(() => decode(`{${REQUIRED},"items":{}}`)).toThrow(MalformedPayloadError)
    expect(() => decode(`{${REQUIRED},"items":"nope"}`)).toThrow(MalformedPayloadError)
    expect(() => decode(`{${REQUIRED},"items":null}`)).toThrow(MalformedPayloadError)
  })

  it('accepts an empty items array', () => {
    expect(decodeWithItems('').items).toEqual([])
  })

  it('rejects an item missing a guaranteed field', () => {
    const complete: Record<string, string> = {
      operation: '"withdrawal"',
      assetType: '"fiat"',
      comparisonType: '"transaction"',
      unit: '"usd_cents"',
      effectiveThreshold: '5000000',
    }
    const item = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    expect(decodeWithItems(item(complete)).items).toHaveLength(1)

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decodeWithItems(item(partial))).toThrow(MalformedPayloadError)
    }
  })

  describe('a transaction-limit item', () => {
    it('decodes with window, currentAggregate, and usagePercent all absent', () => {
      const [item] = decodeWithItems(TRANSACTION_ITEM).items
      expect(item?.window).toBeNull()
      expect(item?.currentAggregate).toBeNull()
      expect(item?.usagePercent).toBeNull()
      expect(item?.comparisonType).toEqual({ kind: 'transaction' })
    })

    it('does not require window, currentAggregate, or usagePercent regardless of comparisonType', () => {
      // Nothing in the decoder branches on comparisonType — an aggregation
      // item that (unusually) omits all three still decodes rather than
      // throwing. See the doc comment on `toAccountLimitsUsageItem`.
      const sparse =
        '{"operation":"deposit","assetType":"fiat","comparisonType":"aggregation",' +
        '"unit":"usd_cents","effectiveThreshold":100}'
      const [item] = decodeWithItems(sparse).items
      expect(item?.window).toBeNull()
      expect(item?.currentAggregate).toBeNull()
      expect(item?.usagePercent).toBeNull()
    })
  })

  describe('an aggregation-limit item', () => {
    it('decodes every field present, unconverted from its documented unit', () => {
      const [item] = decodeWithItems(AGGREGATION_ITEM).items
      expect(item).toEqual({
        operation: { kind: 'send' },
        assetType: { kind: 'crypto' },
        comparisonType: { kind: 'aggregation' },
        window: { kind: 'PT24H' },
        unit: { kind: 'usd_cents' },
        effectiveThreshold: 1000000,
        currentAggregate: 1234567,
        usagePercent: 24.69,
      })
    })

    it('accepts the other documented window value', () => {
      const [item] = decodeWithItems(AGGREGATION_ITEM.replace('PT24H', 'P30D')).items
      expect(item?.window).toEqual({ kind: 'P30D' })
    })
  })

  it('decodes a count-based item without converting the count', () => {
    const [item] = decodeWithItems(COUNT_ITEM).items
    expect(item?.unit).toEqual({ kind: 'count' })
    expect(item?.effectiveThreshold).toBe(10)
  })

  it('decodes a monetary (usd_cents) item as whole cents, not dollars', () => {
    const [item] = decodeWithItems(TRANSACTION_ITEM).items
    expect(item?.unit).toEqual({ kind: 'usd_cents' })
    expect(item?.effectiveThreshold).toBe(5000000)
  })

  it('decodes a full response carrying both a transaction and an aggregation item', () => {
    const usage = decodeWithItems(`${TRANSACTION_ITEM},${AGGREGATION_ITEM}`)
    expect(usage.items).toHaveLength(2)
    expect(usage.items[0]?.comparisonType).toEqual({ kind: 'transaction' })
    expect(usage.items[1]?.comparisonType).toEqual({ kind: 'aggregation' })
  })
})

describe('numeric fields', () => {
  it('rejects effectiveThreshold sent as a string rather than a JSON number', () => {
    expect(() => decodeWithItems(TRANSACTION_ITEM.replace('5000000', '"5000000"'))).toThrow(
      MalformedPayloadError,
    )
  })

  it('rejects a negative effectiveThreshold', () => {
    expect(() => decodeWithItems(TRANSACTION_ITEM.replace('5000000', '-1'))).toThrow(
      MalformedPayloadError,
    )
  })

  it('rejects a non-integer effectiveThreshold', () => {
    expect(() => decodeWithItems(TRANSACTION_ITEM.replace('5000000', '5000000.5'))).toThrow(
      MalformedPayloadError,
    )
  })

  it('rejects a negative currentAggregate', () => {
    expect(() =>
      decodeWithItems(
        AGGREGATION_ITEM.replace('"currentAggregate":1234567', '"currentAggregate":-1'),
      ),
    ).toThrow(MalformedPayloadError)
  })

  it('rejects a non-integer currentAggregate', () => {
    expect(() =>
      decodeWithItems(
        AGGREGATION_ITEM.replace('"currentAggregate":1234567', '"currentAggregate":1.5'),
      ),
    ).toThrow(MalformedPayloadError)
  })

  it('rejects a negative usagePercent', () => {
    expect(() =>
      decodeWithItems(AGGREGATION_ITEM.replace('"usagePercent":24.69', '"usagePercent":-0.01')),
    ).toThrow(MalformedPayloadError)
  })

  it('accepts a non-integer usagePercent (it is a decimal, not a count)', () => {
    const [item] = decodeWithItems(AGGREGATION_ITEM).items
    expect(item?.usagePercent).toBe(24.69)
  })

  it('accepts a zero effectiveThreshold, currentAggregate, and usagePercent', () => {
    const zeroed = AGGREGATION_ITEM.replace('1000000', '0')
      .replace('1234567', '0')
      .replace('24.69', '0')
    const [item] = decodeWithItems(zeroed).items
    expect(item?.effectiveThreshold).toBe(0)
    expect(item?.currentAggregate).toBe(0)
    expect(item?.usagePercent).toBe(0)
  })
})

describe('closed-set fields', () => {
  it('maps every documented operation and falls back for the rest', () => {
    const operations = [
      'deposit',
      'withdrawal',
      'receive',
      'send',
      'send_count',
      'address_linking',
      'fiat_linking',
      'deposit_return_count',
      'balance_cap',
    ]
    for (const operation of operations) {
      const [item] = decodeWithItems(TRANSACTION_ITEM.replace('withdrawal', operation)).items
      expect(item?.operation).toEqual({ kind: operation })
    }

    const [unknown] = decodeWithItems(TRANSACTION_ITEM.replace('withdrawal', 'teleport')).items
    expect(unknown?.operation).toEqual({ kind: 'unrecognized', rawValue: 'teleport' })
  })

  it('maps every documented assetType and falls back for the rest', () => {
    expect(decodeWithItems(TRANSACTION_ITEM.replace('fiat', 'crypto')).items[0]?.assetType).toEqual(
      { kind: 'crypto' },
    )
    const [unknown] = decodeWithItems(TRANSACTION_ITEM.replace('"fiat"', '"stablecoin"')).items
    expect(unknown?.assetType).toEqual({ kind: 'unrecognized', rawValue: 'stablecoin' })
  })

  it('maps every documented comparisonType and falls back for the rest', () => {
    expect(
      decodeWithItems(TRANSACTION_ITEM.replace('transaction', 'aggregation')).items[0]
        ?.comparisonType,
    ).toEqual({ kind: 'aggregation' })
    const [unknown] = decodeWithItems(
      TRANSACTION_ITEM.replace('"transaction"', '"cumulative"'),
    ).items
    expect(unknown?.comparisonType).toEqual({ kind: 'unrecognized', rawValue: 'cumulative' })
  })

  it('maps every documented unit and falls back for the rest', () => {
    expect(decodeWithItems(COUNT_ITEM).items[0]?.unit).toEqual({ kind: 'count' })
    const [unknown] = decodeWithItems(
      TRANSACTION_ITEM.replace('"usd_cents"', '"usd_dollars"'),
    ).items
    expect(unknown?.unit).toEqual({ kind: 'unrecognized', rawValue: 'usd_dollars' })
  })

  it('maps every documented window and falls back for the rest', () => {
    const [unknown] = decodeWithItems(AGGREGATION_ITEM.replace('"PT24H"', '"PT1H"')).items
    expect(unknown?.window).toEqual({ kind: 'unrecognized', rawValue: 'PT1H' })
  })

  it('maps the documented resource type and falls back for the rest', () => {
    expect(decode(`{${REQUIRED},"items":[]}`).type).toEqual({ kind: 'limitsUsage' })
    const unknown = decode(`{${REQUIRED.replace('"limitsUsage"', '"somethingElse"')},"items":[]}`)
    expect(unknown.type).toEqual({ kind: 'unrecognized', rawValue: 'somethingElse' })
  })

  it('treats a value spelled like an Object.prototype member as unrecognized', () => {
    for (const hostile of ['constructor', 'toString', 'hasOwnProperty', '__proto__']) {
      const [item] = decodeWithItems(TRANSACTION_ITEM.replace('withdrawal', hostile)).items
      expect(item?.operation).toEqual({ kind: 'unrecognized', rawValue: hostile })
    }
  })
})

describe('forward compatibility', () => {
  it('ignores an unknown response field wherever it appears', () => {
    const usage = decode(
      `{${REQUIRED},"tier":"gold","items":[${TRANSACTION_ITEM.slice(0, -1)},"extra":"nope"}]}`,
    )
    expect(usage.accountId).toBe(ACCOUNT_ID)
    expect(usage.items).toHaveLength(1)
    expect(Object.keys(usage)).not.toContain('tier')
  })
})

describe('immutability', () => {
  it('freezes the decoded resource and its items', () => {
    const usage = decodeWithItems(`${TRANSACTION_ITEM},${AGGREGATION_ITEM}`)
    expect(Object.isFrozen(usage)).toBe(true)
    expect(Object.isFrozen(usage.items)).toBe(true)
    expect(Object.isFrozen(usage.items[0])).toBe(true)
    expect(Object.isFrozen(usage.items[0]?.operation)).toBe(true)
  })

  it('refuses a write to the resource through a cast', () => {
    const usage = decodeWithItems(TRANSACTION_ITEM)
    const mutable = usage as unknown as Record<string, unknown>
    expect(() => {
      mutable['accountId'] = 'forged'
    }).toThrow(TypeError)
    expect(usage.accountId).toBe(ACCOUNT_ID)
  })

  it('refuses a write to an item through a cast', () => {
    const usage = decodeWithItems(TRANSACTION_ITEM)
    const mutable = usage.items[0] as unknown as Record<string, unknown>
    expect(() => {
      mutable['effectiveThreshold'] = 0
    }).toThrow(TypeError)
    expect(usage.items[0]?.effectiveThreshold).toBe(5000000)
  })
})

describe('no redaction', () => {
  /**
   * Unlike `Money.amount` or a fiat account's `billingDetails`, nothing on
   * this model falls under the SDK's restricted-PII redaction rules or any
   * comparable rule — these are the account's own limit thresholds and usage
   * figures, not a transaction amount or bank/PII detail. So, unlike
   * `Deposit`/`Account`, every value is visible through ordinary rendering.
   */
  it('renders every field through JSON.stringify, util.inspect, and toString', () => {
    const usage = decodeWithItems(AGGREGATION_ITEM)
    for (const rendered of [
      JSON.stringify(usage),
      inspect(usage, { getters: true }),
      String(usage),
    ]) {
      expect(rendered).toContain(ACCOUNT_ID)
    }
    expect(JSON.stringify(usage)).toContain('1234567')
    expect(JSON.stringify(usage)).toContain('24.69')
  })
})

describe('consumer construction', () => {
  it('does not accept a look-alike object as an AccountLimitsUsage', () => {
    const fabricated = { accountId: 'forged', items: [] }
    expect(fabricated instanceof AccountLimitsUsage).toBe(false)
    expect(decodeWithItems('') instanceof AccountLimitsUsage).toBe(true)
  })
})

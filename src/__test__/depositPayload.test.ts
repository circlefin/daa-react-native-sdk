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
import { Deposit } from '../models/Deposit'
import { DepositSummary } from '../models/DepositSummary'
import type { Money } from '../models/Money'
import { MalformedPayloadError } from '../wire/payload'
import { toDeposit, toDepositSummaries, toDepositSummary } from '../wire/depositPayload'

/**
 * Decoding tests for the deposit model. These go through the real parse and
 * mapping rather than constructing a payload object directly, because the wire
 * spellings, the number handling, and the required/optional line are the things
 * under test — see the class note on `Deposit` for why that line does not follow
 * the OpenAPI schema's required marking.
 */

const REQUIRED =
  '"id":"dep-1","amount":{"amount":"10.00","currency":"USD"},"status":"pending",' +
  '"createDate":"2026-01-01T00:00:00Z"'

function decode(body: string): Deposit {
  return toDeposit(JSON.parse(body) as unknown)
}

function decodeComplete(extra = ''): Deposit {
  return decode(`{${REQUIRED}${extra === '' ? '' : `,${extra}`}}`)
}

function depositWith(field: string, value: string): Deposit {
  return decodeComplete(`"${field}":${value}`)
}

describe('required and optional fields', () => {
  it('rejects a response missing any guaranteed field', () => {
    const complete: Record<string, string> = {
      id: '"dep-1"',
      amount: '{"amount":"10.00","currency":"USD"}',
      status: '"pending"',
      createDate: '"2026-01-01T00:00:00Z"',
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    // Sanity: the complete body decodes, or every assertion below is vacuous.
    expect(decode(body(complete)).id).toBe('dep-1')

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decode(body(partial))).toThrow(MalformedPayloadError)
    }

    expect(() => decode('{}')).toThrow(MalformedPayloadError)
    expect(() => toDeposit(null)).toThrow(MalformedPayloadError)
    expect(() => toDeposit([])).toThrow(MalformedPayloadError)
  })

  it('rejects an explicit null on a guaranteed field', () => {
    expect(() =>
      decode(
        '{"id":null,"amount":{"amount":"10.00","currency":"USD"},"status":"pending",' +
          '"createDate":"2026-01-01T00:00:00Z"}',
      ),
    ).toThrow(MalformedPayloadError)
  })

  it('rejects a field carried in the wrong shape', () => {
    expect(() => depositWith('id', '{}')).toThrow(MalformedPayloadError)
    expect(() => depositWith('id', 'true')).toThrow(MalformedPayloadError)
    expect(() => depositWith('amount', '"nope"')).toThrow(MalformedPayloadError)
    expect(() => depositWith('createDate', '7')).toThrow(MalformedPayloadError)
  })

  /**
   * `destination` is marked required in the schema, but the service reports a
   * `null` destination whenever the ledger leg is not a wallet location — a
   * real code path. Absence must decode cleanly, not throw.
   */
  it('tolerates an absent destination despite the schema marking it required', () => {
    expect(decodeComplete().destination).toBeNull()
  })

  it('tolerates an absent update date', () => {
    expect(decodeComplete().updateDate).toBeNull()
  })

  it('reports every other absent optional field as absent', () => {
    const deposit = decodeComplete()
    expect(deposit.sourceAccountId).toBeNull()
    expect(deposit.fee).toBeNull()
    expect(deposit.fees).toBeNull()
    expect(deposit.fromAmount).toBeNull()
    expect(deposit.errorCode).toBeNull()
    expect(deposit.externalRef).toBeNull()
    expect(deposit.customerExternalRef).toBeNull()
    expect(deposit.riskEvaluation).toBeNull()
    expect(deposit.source).toBeNull()
    expect(deposit.trackingRef).toBeNull()
  })

  it('rejects an optional money field carried in the wrong shape', () => {
    expect(() => depositWith('fee', '"nope"')).toThrow(MalformedPayloadError)
    expect(() => depositWith('fee', '{"amount":"nope","currency":"USD"}')).toThrow(
      MalformedPayloadError,
    )
  })

  it('rejects a destination missing its guaranteed id or type', () => {
    expect(() => depositWith('destination', '{"type":"account"}')).toThrow(MalformedPayloadError)
    expect(() => depositWith('destination', '{"id":"acct-1"}')).toThrow(MalformedPayloadError)
  })

  it('rejects a source missing its guaranteed id or type', () => {
    expect(() => depositWith('source', '{"type":"wire"}')).toThrow(MalformedPayloadError)
    expect(() => depositWith('source', '{"id":"fiat-1"}')).toThrow(MalformedPayloadError)
  })
})

describe('closed-set fields', () => {
  it('maps every known status and falls back for the rest', () => {
    expect(depositWith('status', '"pending"').status).toEqual({ kind: 'pending' })
    expect(depositWith('status', '"complete"').status).toEqual({ kind: 'complete' })
    expect(depositWith('status', '"failed"').status).toEqual({ kind: 'failed' })
    expect(depositWith('status', '"settling"').status).toEqual({
      kind: 'unrecognized',
      rawValue: 'settling',
    })
  })

  it('treats a value spelled like an Object.prototype member as unrecognized', () => {
    for (const hostile of ['constructor', 'toString', 'hasOwnProperty', '__proto__']) {
      expect(depositWith('status', `"${hostile}"`).status).toEqual({
        kind: 'unrecognized',
        rawValue: hostile,
      })
    }
  })

  it('maps every known destination type and falls back for the rest', () => {
    expect(depositWith('destination', '{"type":"account","id":"acct-1"}').destination).toEqual({
      kind: 'account',
      accountId: 'acct-1',
    })
    expect(depositWith('destination', '{"type":"blockchain","id":"acct-1"}').destination).toEqual({
      kind: 'unrecognized',
      rawValue: 'blockchain',
    })
  })

  it('maps every known source rail and falls back for the rest', () => {
    const wire = depositWith('source', '{"type":"wire","id":"fiat-1","name":"Checking"}').source
    expect(wire).toEqual({ type: { kind: 'wire' }, id: 'fiat-1', name: 'Checking' })

    const unknownRail = depositWith('source', '{"type":"venmo","id":"fiat-1"}').source
    expect(unknownRail).toEqual({
      type: { kind: 'unrecognized', rawValue: 'venmo' },
      id: 'fiat-1',
      name: null,
    })
  })
})

describe('money fields', () => {
  it('preserves an amount that a JavaScript number would round', () => {
    const deposit = depositWith('amount', '{"amount":"1234567890123456.78","currency":"USD"}')
    expect((deposit.amount as Money).amount).toBe('1234567890123456.78')
    expect((deposit.amount as Money).currency).toBe('USD')
  })

  it('rejects an amount sent as a JSON number rather than coercing it', () => {
    expect(() => depositWith('amount', '{"amount":10.5,"currency":"USD"}')).toThrow(
      MalformedPayloadError,
    )
  })

  it('decodes the optional money fields when present', () => {
    const deposit = decodeComplete(
      '"fee":{"amount":"1.00","currency":"USD"},' +
        '"fees":{"amount":"1.50","currency":"USD"},' +
        '"fromAmount":{"amount":"9.00","currency":"EUR"}',
    )
    expect((deposit.fee as Money).amount).toBe('1.00')
    expect((deposit.fees as Money).amount).toBe('1.50')
    expect((deposit.fromAmount as Money).amount).toBe('9.00')
    expect((deposit.fromAmount as Money).currency).toBe('EUR')
  })
})

describe('risk evaluation', () => {
  it('carries a risk decision when present', () => {
    const deposit = decodeComplete('"riskEvaluation":{"decision":"denied","reason":"velocity"}')
    expect(deposit.riskEvaluation).toEqual({ decision: 'denied', reason: 'velocity' })
  })

  it('tolerates a risk decision with no reason', () => {
    const deposit = decodeComplete('"riskEvaluation":{"decision":"denied"}')
    expect(deposit.riskEvaluation).toEqual({ decision: 'denied', reason: null })
  })

  it('tolerates a reason-only risk evaluation the service can produce', () => {
    const deposit = decodeComplete('"riskEvaluation":{"reason":"velocity"}')
    expect(deposit.riskEvaluation).toEqual({ decision: null, reason: 'velocity' })
  })

  it('rejects a risk evaluation field carried in the wrong shape', () => {
    expect(() => decodeComplete('"riskEvaluation":{"decision":7}')).toThrow(MalformedPayloadError)
  })
})

describe('forward compatibility', () => {
  it('ignores an unknown response field wherever it appears', () => {
    const deposit = decode(
      `{${REQUIRED},"settlementTier":"gold","riskScore":7,"flags":null,` +
        `"destination":{"type":"account","id":"acct-1","extra":"nope"}}`,
    )
    expect(deposit.id).toBe('dep-1')
    expect(deposit.destination).toEqual({ kind: 'account', accountId: 'acct-1' })
    expect(Object.keys(deposit)).not.toContain('settlementTier')
    expect(Object.keys(deposit)).not.toContain('riskScore')
  })

  it('decodes a response carrying an unknown field and an unknown value at once', () => {
    const deposit = decode(`{${REQUIRED},"status":"settling","tierMetadata":{"a":1}}`)
    expect(deposit.id).toBe('dep-1')
    expect(deposit.status).toEqual({ kind: 'unrecognized', rawValue: 'settling' })
  })
})

describe('redaction', () => {
  const deposit = decodeComplete(
    '"fee":{"amount":"5.25","currency":"USD"},' +
      '"destination":{"type":"account","id":"acct-1"},' +
      '"externalRef":"bank-ref-123","customerExternalRef":"customer memo 456"',
  )
  const secrets = ['10.00', '5.25', 'bank-ref-123', 'customer memo 456']

  it('keeps sensitive fields off the deposit object as own properties', () => {
    expect(Object.getOwnPropertyNames(deposit)).not.toContain('amount')
    expect(Object.getOwnPropertyNames(deposit)).not.toContain('fee')
    expect(Object.getOwnPropertyNames(deposit)).not.toContain('fees')
    expect(Object.getOwnPropertyNames(deposit)).not.toContain('fromAmount')
    expect(Object.getOwnPropertyNames(deposit)).not.toContain('externalRef')
    expect(Object.getOwnPropertyNames(deposit)).not.toContain('customerExternalRef')
  })

  it('keeps sensitive values available through explicit accessors', () => {
    expect(deposit.externalRef).toBe('bank-ref-123')
    expect(deposit.customerExternalRef).toBe('customer memo 456')
  })

  it.each([
    ['JSON.stringify', (value: unknown): string => JSON.stringify(value) ?? ''],
    ['util.inspect (what console.log renders)', (value: unknown): string => inspect(value)],
    ['String()', (value: unknown): string => String(value)],
    [
      'spread into a plain object',
      (value: unknown): string => JSON.stringify({ ...(value as object) }) ?? '',
    ],
    [
      'for...in',
      (value: unknown): string => {
        let out = ''
        for (const key in value as Record<string, unknown>) {
          out += `${key}=${String((value as Record<string, unknown>)[key])};`
        }
        return out
      },
    ],
  ])('reveals no sensitive value through %s', (_name, render) => {
    for (const rendered of [render(deposit), render(deposit.amount), render(deposit.fee)]) {
      for (const secret of secrets) {
        expect(rendered).not.toContain(secret)
      }
    }
  })

  it('still renders the identifiers and states that make a log line useful', () => {
    expect(String(deposit)).toContain('dep-1')
    expect(String(deposit)).toContain('pending')
    expect(JSON.stringify(deposit)).toContain('dep-1')
  })
})

describe('immutability', () => {
  const deposit = decodeComplete()

  it('freezes the deposit', () => {
    expect(Object.isFrozen(deposit)).toBe(true)
  })

  /**
   * Freezing the deposit alone is not enough: the nested values it hands out are
   * ordinary objects, so a consumer reaching one could edit an account id, a
   * rail, or a risk decision on a deposit the SDK already returned. The
   * guarantee is only worth stating if it reaches the whole graph.
   */
  it('freezes every nested value it decoded, not only the deposit', () => {
    const full = decodeComplete(
      '"destination":{"type":"account","id":"acct-1"},' +
        '"source":{"type":"wire","id":"fiat-1","name":"Checking"},' +
        '"riskEvaluation":{"decision":"denied","reason":"velocity"}',
    )

    expect(Object.isFrozen(full.destination)).toBe(true)
    expect(Object.isFrozen(full.source)).toBe(true)
    expect(Object.isFrozen(full.source?.type)).toBe(true)
    expect(Object.isFrozen(full.riskEvaluation)).toBe(true)
    expect(Object.isFrozen(full.status)).toBe(true)

    // An unrecognized arm is decoded rather than looked up, so it is the one
    // most likely to be missed.
    const unknown = decodeComplete('"destination":{"type":"blockchain","id":"acct-1"}')
    expect(Object.isFrozen(unknown.destination)).toBe(true)
  })

  it('refuses a write to a nested value through a cast', () => {
    const full = decodeComplete('"destination":{"type":"account","id":"acct-1"}')
    const mutable = full.destination as unknown as Record<string, unknown>

    expect(() => {
      mutable['accountId'] = 'acct-forged'
    }).toThrow(TypeError)
    expect(full.destination).toEqual({ kind: 'account', accountId: 'acct-1' })
  })

  it('refuses a write through a cast', () => {
    const mutable = deposit as unknown as Record<string, unknown>
    expect(() => {
      mutable['id'] = 'dep-forged'
    }).toThrow(TypeError)
    expect(deposit.id).toBe('dep-1')
  })
})

describe('consumer construction', () => {
  it('does not accept a look-alike object as a deposit', () => {
    const fabricated = {
      id: 'dep-forged',
      status: { kind: 'pending' },
    }
    expect(fabricated instanceof Deposit).toBe(false)
    expect(decodeComplete() instanceof Deposit).toBe(true)
  })
})

/**
 * `toDepositSummary` decoding — the compact list-endpoint projection.
 *
 * Same required/optional line as `toDeposit` (both wire records
 * carry the same guaranteed fields), but the summary's own wire record has no
 * `source`, `fees`, `fromAmount`, or `trackingRef` property at all, so there is
 * nothing to assert absent for those — see `models/DepositSummary.ts`'s class
 * note.
 */
describe('DepositSummary decoding', () => {
  function decodeSummary(body: string): DepositSummary {
    return toDepositSummary(JSON.parse(body) as unknown)
  }

  function decodeSummaryComplete(extra = ''): DepositSummary {
    return decodeSummary(`{${REQUIRED}${extra === '' ? '' : `,${extra}`}}`)
  }

  it('rejects a response missing any guaranteed field', () => {
    const complete: Record<string, string> = {
      id: '"dep-1"',
      amount: '{"amount":"10.00","currency":"USD"}',
      status: '"pending"',
      createDate: '"2026-01-01T00:00:00Z"',
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    expect(decodeSummary(body(complete)).id).toBe('dep-1')

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decodeSummary(body(partial))).toThrow(MalformedPayloadError)
    }

    expect(() => toDepositSummary(null)).toThrow(MalformedPayloadError)
    expect(() => toDepositSummary([])).toThrow(MalformedPayloadError)
  })

  it('tolerates an absent destination and an absent update date', () => {
    const summary = decodeSummaryComplete()
    expect(summary.destination).toBeNull()
    expect(summary.updateDate).toBeNull()
  })

  it('reports every other absent optional field as absent', () => {
    const summary = decodeSummaryComplete()
    expect(summary.sourceAccountId).toBeNull()
    expect(summary.fee).toBeNull()
    expect(summary.errorCode).toBeNull()
    expect(summary.externalRef).toBeNull()
    expect(summary.customerExternalRef).toBeNull()
    expect(summary.riskEvaluation).toBeNull()
  })

  it('maps every known status and falls back for the rest', () => {
    expect(decodeSummary(`{${REQUIRED.replace('"pending"', '"complete"')}}`).status).toEqual({
      kind: 'complete',
    })
    expect(decodeSummary(`{${REQUIRED.replace('"pending"', '"settling"')}}`).status).toEqual({
      kind: 'unrecognized',
      rawValue: 'settling',
    })
  })

  it('decodes destination and the single fee field when present', () => {
    const summary = decodeSummaryComplete(
      '"destination":{"type":"account","id":"acct-1"},"fee":{"amount":"1.00","currency":"USD"}',
    )
    expect(summary.destination).toEqual({ kind: 'account', accountId: 'acct-1' })
    expect((summary.fee as Money).amount).toBe('1.00')
  })

  it('has no source, fees, fromAmount, or trackingRef fields at all', () => {
    const summary = decodeSummaryComplete()
    expect(Object.getOwnPropertyNames(summary)).not.toContain('source')
    expect(Object.getOwnPropertyNames(summary)).not.toContain('fees')
    expect(Object.getOwnPropertyNames(summary)).not.toContain('fromAmount')
    expect(Object.getOwnPropertyNames(summary)).not.toContain('trackingRef')
  })

  it('withholds amounts and references from default renderings', () => {
    const summary = decodeSummaryComplete(
      '"fee":{"amount":"5.25","currency":"USD"},"externalRef":"bank-ref-123",' +
        '"customerExternalRef":"customer memo 456"',
    )
    const rendered = JSON.stringify(summary)
    for (const secret of ['10.00', '5.25', 'bank-ref-123', 'customer memo 456']) {
      expect(rendered).not.toContain(secret)
    }
    expect(summary.externalRef).toBe('bank-ref-123')
    expect(summary.customerExternalRef).toBe('customer memo 456')
  })

  it('freezes the summary', () => {
    expect(Object.isFrozen(decodeSummaryComplete())).toBe(true)
  })

  it('does not accept a look-alike object as a DepositSummary', () => {
    const fabricated = { id: 'dep-forged', status: { kind: 'pending' } }
    expect(fabricated instanceof DepositSummary).toBe(false)
    expect(decodeSummaryComplete() instanceof DepositSummary).toBe(true)
  })

  it('decodes a page of summaries and rejects a non-array collection', () => {
    const items = toDepositSummaries(JSON.parse(`[{${REQUIRED}}]`) as unknown)
    expect(items).toHaveLength(1)
    expect(items[0]?.id).toBe('dep-1')
    expect(Object.isFrozen(items)).toBe(true)
    expect(() => toDepositSummaries(JSON.parse(`{${REQUIRED}}`) as unknown)).toThrow(
      MalformedPayloadError,
    )
  })
})

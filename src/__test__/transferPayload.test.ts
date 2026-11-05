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
import type { Money } from '../models/Money'
import {
  Transfer,
  TransferDestinationAccountLocation,
  TransferDestinationBlockchainLocation,
} from '../models/Transfer'
import { MalformedPayloadError } from '../wire/payload'
import { toTransfer } from '../wire/transferPayload'

/**
 * Decoding tests for the transfer model. As in `accountPayload.test.ts`, these
 * go through the real parse and mapping rather than constructing a payload
 * object directly — the wire spellings, the required/optional line, and the
 * polymorphic locations are the things under test.
 */

/**
 * A representative complete transfer. Only `id`, `amount`, and `status` are
 * actually guaranteed (see `models/Transfer.ts`'s file-level note on why the
 * OpenAPI schema's required marking is not proof) — `source` and `destination`
 * are included here too so most tests below exercise an ordinary account leg
 * rather than the fiat-absent edge case, which is covered on its own further
 * down.
 */
const REQUIRED =
  '"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
  '"destination":{"type":"account","id":"acct-dst"},' +
  '"amount":{"amount":"10.00","currency":"USD"},"status":"pending"'

function decode(body: string): Transfer {
  return toTransfer(JSON.parse(body) as unknown)
}

function decodeComplete(extra = ''): Transfer {
  return decode(`{${REQUIRED}${extra === '' ? '' : `,${extra}`}}`)
}

describe('required and optional fields', () => {
  /**
   * A response missing something the service actually guarantees is malformed,
   * not a transfer with holes in it — same rule as `Account`. Only `id`,
   * `amount`, and `status` belong in this set: `source`/`destination` are marked
   * required in the same way but the service can omit them (see the
   * `locations` describe block below), so they are deliberately excluded here
   * rather than trusted on the schema alone.
   */
  it('rejects a response missing any guaranteed field', () => {
    const complete: Record<string, string> = {
      id: '"tr-1"',
      amount: '{"amount":"10.00","currency":"USD"}',
      status: '"pending"',
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    // Sanity: the complete body decodes, or every assertion below is vacuous.
    expect(decode(body(complete)).id).toBe('tr-1')

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decode(body(partial))).toThrow(MalformedPayloadError)
    }

    expect(() => decode('{}')).toThrow(MalformedPayloadError)
    expect(() => toTransfer(null)).toThrow(MalformedPayloadError)
    expect(() => toTransfer([])).toThrow(MalformedPayloadError)
  })

  it('rejects an explicit null on a guaranteed field', () => {
    expect(() =>
      decode(
        '{"id":null,"source":{"type":"account","id":"a"},' +
          '"destination":{"type":"account","id":"b"},' +
          '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
      ),
    ).toThrow(MalformedPayloadError)
  })

  it('rejects a field carried in the wrong shape', () => {
    expect(() => decodeComplete('"id":7')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"transactionHash":true')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"destinationTransactionHash":true')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"source":"nope"')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"policyEvaluation":"nope"')).toThrow(MalformedPayloadError)
  })

  /** A JSON number in the amount field is a shape error, not a value to coerce — see `Money`. */
  it('rejects a transfer amount sent as a JSON number rather than coercing it', () => {
    expect(() =>
      decode(
        '{"id":"tr-1","source":{"type":"account","id":"a"},' +
          '"destination":{"type":"account","id":"b"},' +
          '"amount":{"amount":10.5,"currency":"USD"},"status":"pending"}',
      ),
    ).toThrow(MalformedPayloadError)
  })

  /**
   * `createDate` is not marked required in the OpenAPI schema at all, unlike
   * `id`/`amount`/`status` — the same kind of gap as `Account.description`,
   * which the service can omit. Treated as optional here rather than rejecting
   * an otherwise-readable transfer.
   */
  it('tolerates a transfer with no createDate', () => {
    expect(decodeComplete().createDate).toBeNull()
    expect(decodeComplete('"createDate":"2026-01-01T00:00:00Z"').createDate).toBe(
      '2026-01-01T00:00:00Z',
    )
  })

  it('reports every other absent optional field as absent', () => {
    const transfer = decodeComplete()
    expect(transfer.transactionHash).toBeNull()
    expect(transfer.destinationTransactionHash).toBeNull()
    expect(transfer.errorCode).toBeNull()
    expect(transfer.policyEvaluation).toBeNull()
    expect(transfer.fees).toEqual([])
  })

  it('carries transactionHash, errorCode, and policyEvaluation when present', () => {
    const transfer = decodeComplete(
      '"transactionHash":"0xhash","status":"failed","errorCode":"insufficient_funds",' +
        '"policyEvaluation":{"status":"approved"}',
    )
    expect(transfer.transactionHash).toBe('0xhash')
    expect(transfer.errorCode).toEqual({ kind: 'insufficient_funds' })
    expect(transfer.policyEvaluation).toEqual({ status: 'approved' })
  })

  /**
   * `destinationTransactionHash` is the CCTP destination-mint hash — a
   * distinct field from the source-side `transactionHash`, present only once
   * the destination leg has minted.
   */
  it('carries destinationTransactionHash when present, independently of transactionHash', () => {
    const transfer = decodeComplete(
      '"transactionHash":"0xsource","destinationTransactionHash":"0xdestination"',
    )
    expect(transfer.transactionHash).toBe('0xsource')
    expect(transfer.destinationTransactionHash).toBe('0xdestination')
  })
})

describe('closed-set fields', () => {
  it('maps every known status and falls back for the rest', () => {
    expect(decodeComplete('"status":"pending"').status).toEqual({ kind: 'pending' })
    expect(decodeComplete('"status":"complete"').status).toEqual({ kind: 'complete' })
    expect(decodeComplete('"status":"failed"').status).toEqual({ kind: 'failed' })
    // A value the service adds later must read as unrecognized rather than
    // failing the whole transfer, and must keep the string.
    expect(decodeComplete('"status":"settling"').status).toEqual({
      kind: 'unrecognized',
      rawValue: 'settling',
    })
  })

  it('maps every known error code and falls back for the rest', () => {
    for (const code of [
      'transfer_failed',
      'transfer_denied',
      'blockchain_error',
      'insufficient_funds',
      'invalid_crypto_address',
    ]) {
      expect(decodeComplete(`"errorCode":"${code}"`).errorCode).toEqual({ kind: code })
    }
    expect(decodeComplete('"errorCode":"self_sends_unsupported"').errorCode).toEqual({
      kind: 'unrecognized',
      rawValue: 'self_sends_unsupported',
    })
  })

  /** `errorCode` absent is `null` — a distinct state from an unrecognized-but-present value. */
  it('treats an absent errorCode as null, not unrecognized', () => {
    expect(decodeComplete().errorCode).toBeNull()
  })

  /** A JavaScript hazard with no Kotlin/Swift equivalent — see `accountPayload.test.ts`'s identical case. */
  it('treats a value spelled like an Object.prototype member as unrecognized', () => {
    for (const hostile of ['constructor', 'toString', 'hasOwnProperty', '__proto__']) {
      expect(decodeComplete(`"status":"${hostile}"`).status).toEqual({
        kind: 'unrecognized',
        rawValue: hostile,
      })
    }
  })
})

describe('locations', () => {
  it('decodes an account source location', () => {
    const transfer = decodeComplete()
    expect(transfer.source).toEqual({ kind: 'account', accountId: 'acct-src' })
  })

  it('decodes a blockchain source location', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"blockchain","chain":"ETH"},' +
        '"destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toEqual({ kind: 'blockchain', chain: 'ETH' })
  })

  /**
   * `chain` is nullable on a source blockchain leg, despite the OpenAPI schema
   * marking `TransferSourceBlockchainLocation.chain` required: the service can
   * return a source blockchain leg with no `chain`. Rejecting it would reject a
   * real, ordinary transfer.
   */
  it('decodes a blockchain source location with no chain metadata as a null chain', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"blockchain"},' +
        '"destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toEqual({ kind: 'blockchain', chain: null })
  })

  /** A source location kind this SDK does not recognise degrades rather than failing the read. */
  it('falls back to unrecognized for a source location kind it does not recognise', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"wire","routingNumber":"1"},' +
        '"destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toEqual({ kind: 'unrecognized', rawValue: 'wire' })
  })

  /**
   * `source`/`destination` are themselves optional: the service reports no leg
   * for a fiat source or destination, and a fiat leg — an ordinary
   * onramp/offramp — is a real, common transfer. The service omits a null leg,
   * so it is simply absent from the JSON body, which is exactly what these
   * payloads simulate.
   */
  it('decodes a transfer with a fiat source (an onramp) as a null source', () => {
    const transfer = decode(
      '{"id":"tr-1","destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toBeNull()
    expect(transfer.destination).toEqual({ kind: 'account', accountId: 'acct-dst' })
  })

  it('decodes a transfer with a fiat destination (an offramp) as a null destination', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toEqual({ kind: 'account', accountId: 'acct-src' })
    expect(transfer.destination).toBeNull()
  })

  /** A verified-blockchain source also has no leg — a transfer can lack both legs at once. */
  it('decodes a transfer with neither a source nor a destination as both null', () => {
    const transfer = decode(
      '{"id":"tr-1","amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toBeNull()
    expect(transfer.destination).toBeNull()
  })

  /** An explicit JSON `null` is treated the same as an absent key, consistent with every other optional field. */
  it('treats an explicit null source or destination the same as an absent one', () => {
    const transfer = decode(
      '{"id":"tr-1","source":null,"destination":null,' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.source).toBeNull()
    expect(transfer.destination).toBeNull()
  })

  it('decodes an account destination location with no on-chain deposit fields', () => {
    const transfer = decodeComplete()
    const destination = transfer.destination as TransferDestinationAccountLocation
    expect(destination).toBeInstanceOf(TransferDestinationAccountLocation)
    expect(destination.kind).toBe('account')
    expect(destination.accountId).toBe('acct-dst')
    expect(destination.address).toBeNull()
    expect(destination.addressTag).toBeNull()
  })

  it('decodes an account destination location that received an on-chain deposit', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"account","id":"acct-dst","address":"0xdeposit","addressTag":"tag-1"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    const destination = transfer.destination as TransferDestinationAccountLocation
    expect(destination.address).toBe('0xdeposit')
    expect(destination.addressTag).toBe('tag-1')
  })

  it('decodes a blockchain destination location', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"blockchain","chain":"ETH","address":"0xdest","addressTag":null},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    const destination = transfer.destination as TransferDestinationBlockchainLocation
    expect(destination).toBeInstanceOf(TransferDestinationBlockchainLocation)
    expect(destination.kind).toBe('blockchain')
    expect(destination.chain).toBe('ETH')
    expect(destination.address).toBe('0xdest')
    expect(destination.addressTag).toBeNull()
  })

  /**
   * `address` is nullable on a destination blockchain leg, despite the OpenAPI
   * schema marking it required: the service can return a destination
   * `type: "blockchain"` leg with no `address`. Rejecting a null address would
   * reject that real case.
   */
  it('decodes a blockchain destination location with no address as a null address', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"blockchain","chain":"ETH"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    const destination = transfer.destination as TransferDestinationBlockchainLocation
    expect(destination.chain).toBe('ETH')
    expect(destination.address).toBeNull()
  })

  /** `chain` on a destination blockchain leg is nullable, as on the source shape: the service can omit it. */
  it('decodes a blockchain destination location with no chain as a null chain', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"blockchain","address":"0xdest"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    const destination = transfer.destination as TransferDestinationBlockchainLocation
    expect(destination.chain).toBeNull()
    expect(destination.address).toBe('0xdest')
  })

  /** A destination location kind this SDK does not recognise degrades rather than failing the read. */
  it('falls back to unrecognized for a destination location kind it does not recognise', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"verified_blockchain","addressId":"addr-1"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    expect(transfer.destination).toEqual({ kind: 'unrecognized', rawValue: 'verified_blockchain' })
  })

  /** A missing `type` discriminator is malformed — it is the one field every location shape requires. */
  it('rejects a source or destination location missing the type discriminator', () => {
    expect(() =>
      decode(
        '{"id":"tr-1","source":{"id":"acct-src"},' +
          '"destination":{"type":"account","id":"acct-dst"},' +
          '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
      ),
    ).toThrow(MalformedPayloadError)
    expect(() =>
      decode(
        '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
          '"destination":{"id":"acct-dst"},' +
          '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
      ),
    ).toThrow(MalformedPayloadError)
  })
})

describe('fees', () => {
  it('decodes an empty fee list as an empty list', () => {
    expect(decodeComplete().fees).toEqual([])
  })

  it('decodes one or more fees', () => {
    const transfer = decodeComplete(
      '"fees":[{"amount":"0.50","currency":"USD","type":"network"},' +
        '{"amount":"0.01","currency":"ETH","type":"network"}]',
    )
    expect(transfer.fees).toHaveLength(2)
    expect((transfer.fees[0]?.amount as Money).amount).toBe('0.50')
    expect((transfer.fees[0]?.amount as Money).currency).toBe('USD')
    expect(transfer.fees[0]?.type).toBe('network')
    expect((transfer.fees[1]?.amount as Money).amount).toBe('0.01')
  })

  it('rejects a fee entry missing a guaranteed field', () => {
    expect(() => decodeComplete('"fees":[{"currency":"USD","type":"network"}]')).toThrow(
      MalformedPayloadError,
    )
    expect(() => decodeComplete('"fees":[{"amount":"1","currency":"USD"}]')).toThrow(
      MalformedPayloadError,
    )
    expect(() => decodeComplete('"fees":[{"amount":"1","type":"network"}]')).toThrow(
      MalformedPayloadError,
    )
  })

  it('rejects fees carried in the wrong shape', () => {
    expect(() => decodeComplete('"fees":{}')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"fees":["not-an-object"]')).toThrow(MalformedPayloadError)
  })
})

describe('forward compatibility', () => {
  /**
   * Forward-compatible decoding, same pairing as `accountPayload.test.ts`:
   * an unknown response field and an unrecognised closed-set/location value
   * decode together without failing the read.
   */
  it('ignores unknown response fields wherever they appear', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src","futureField":true},' +
        '"destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"1","currency":"USD","futureScale":"2"},"status":"pending",' +
        '"settlementTier":"gold","fees":[{"amount":"0.1","currency":"USD","type":"network","meta":{}}]}',
    )
    expect(transfer.id).toBe('tr-1')
    expect(transfer.source).toEqual({ kind: 'account', accountId: 'acct-src' })
    expect(transfer.fees).toHaveLength(1)
    expect(Object.keys(transfer)).not.toContain('settlementTier')
  })

  it('decodes a response carrying an unknown field and an unknown status at once', () => {
    const transfer = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"settling","tierMetadata":{"a":1}}',
    )
    expect(transfer.id).toBe('tr-1')
    expect(transfer.status).toEqual({ kind: 'unrecognized', rawValue: 'settling' })
  })
})

describe('redaction', () => {
  const transfer = decode(
    '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
      '"destination":{"type":"blockchain","chain":"ETH","address":"0xSECRET","addressTag":"tag-SECRET"},' +
      '"amount":{"amount":"12345.67","currency":"USD"},"status":"pending",' +
      '"fees":[{"amount":"99.99","currency":"USD","type":"network"}]}',
  )
  const secrets = ['0xSECRET', 'tag-SECRET', '12345.67', '99.99']

  it('keeps every sensitive value off the transfer object as an own property', () => {
    expect(Object.getOwnPropertyNames(transfer).sort()).toEqual(
      [
        'id',
        'source',
        'destination',
        'status',
        'errorCode',
        'transactionHash',
        'destinationTransactionHash',
        'policyEvaluation',
        'createDate',
      ].sort(),
    )
    expect(Object.getOwnPropertyNames(transfer.destination as object).sort()).toEqual(
      ['kind', 'chain'].sort(),
    )
    expect(Object.getOwnPropertyNames(transfer.fees[0] as object).sort()).toEqual(
      ['amount', 'type'].sort(),
    )
  })

  it.each([
    ['JSON.stringify', (value: unknown): string => JSON.stringify(value) ?? ''],
    ['util.inspect (what console.log renders)', (value: unknown): string => inspect(value)],
    ['util.inspect at full depth', (value: unknown): string => inspect(value, { depth: null })],
    ['String()', (value: unknown): string => String(value)],
    ['template literal', (value: unknown): string => `${String(value)}`],
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
    for (const rendered of [
      render(transfer),
      render(transfer.destination),
      render(transfer.amount),
      render(transfer.fees),
      render(transfer.fees[0]),
      render((transfer.fees[0] as { amount: unknown }).amount),
    ]) {
      for (const secret of secrets) {
        expect(rendered).not.toContain(secret)
      }
    }
  })

  /**
   * The account-leg redaction path is separate code from the blockchain-leg
   * one above (`TransferDestinationAccountLocation` vs.
   * `TransferDestinationBlockchainLocation`), so it needs its own case rather
   * than trusting the blockchain leg's coverage to stand in for it.
   */
  it('reveals no sensitive value on a destination account leg that received a deposit', () => {
    const accountDestination = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"account","id":"acct-dst","address":"0xACCTSECRET","addressTag":"tag-ACCTSECRET"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    const accountSecrets = ['0xACCTSECRET', 'tag-ACCTSECRET']

    for (const rendered of [
      JSON.stringify(accountDestination.destination),
      inspect(accountDestination.destination),
      inspect(accountDestination.destination, { depth: null }),
      String(accountDestination.destination),
      `${String(accountDestination.destination)}`,
      JSON.stringify({ ...(accountDestination.destination as object) }),
    ]) {
      for (const secret of accountSecrets) {
        expect(rendered).not.toContain(secret)
      }
    }
    expect(JSON.parse(JSON.stringify(accountDestination.destination))).toMatchObject({
      address: '<redacted>',
      addressTag: '<redacted>',
    })
  })

  it('still renders the identifiers and states that make a log line useful', () => {
    expect(String(transfer)).toContain('tr-1')
    expect(String(transfer)).toContain('pending')
    expect(JSON.stringify(transfer)).toContain('tr-1')
    expect(inspect(transfer)).toContain('tr-1')
    // The chain is not sensitive and still renders on the destination leg.
    expect(String(transfer.destination)).toContain('ETH')
    expect(JSON.stringify(transfer.destination)).toContain('ETH')
  })

  it('renders a fee count in place of the fees, and the amount withheld', () => {
    expect(String(transfer)).toContain('fees=1 entries')
    expect(JSON.parse(JSON.stringify(transfer))).toMatchObject({ fees: '1 entries' })
    expect(JSON.parse(JSON.stringify(transfer))).toMatchObject({
      amount: { amount: '<redacted>', currency: 'USD' },
    })
  })

  it('says the destination address was withheld rather than omitting it silently', () => {
    expect(String(transfer.destination)).toContain('address=<redacted>')
    expect(JSON.parse(JSON.stringify(transfer.destination))).toMatchObject({
      address: '<redacted>',
      addressTag: '<redacted>',
    })
  })

  /** A destination account leg that never received a deposit reports `null`, not a redacted placeholder. */
  it('reports a null destination account address as null rather than as withheld', () => {
    const noDeposit = decodeComplete()
    const destination = noDeposit.destination as TransferDestinationAccountLocation
    expect(String(destination)).toContain('address=null')
    expect(JSON.parse(JSON.stringify(destination))).toMatchObject({
      address: null,
      addressTag: null,
    })
  })

  /**
   * The same as above, but for a destination blockchain leg with no address —
   * the folded verified-blockchain-with-no-metadata case. A `null` address must
   * render as `null`, not as a redacted placeholder that implies a secret is
   * being withheld when there is none.
   */
  it('reports a null destination blockchain address and chain as null rather than as withheld', () => {
    const noMetadata = decode(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"blockchain"},' +
        '"amount":{"amount":"1","currency":"USD"},"status":"pending"}',
    )
    const destination = noMetadata.destination as TransferDestinationBlockchainLocation
    expect(String(destination)).toContain('chain=null')
    expect(String(destination)).toContain('address=null')
    expect(JSON.parse(JSON.stringify(destination))).toMatchObject({
      chain: null,
      address: null,
      addressTag: null,
    })
  })

  /** The honest limit, same as `Money`/`Account`: an inspector explicitly asked to evaluate accessors sees everything. */
  it('does not withhold from an inspector explicitly asked to evaluate accessors', () => {
    const revealing = inspect(transfer, { showHidden: true, getters: true, depth: null })
    expect(revealing).toContain('12345.67')
    expect(revealing).toContain('0xSECRET')
    expect((transfer.amount as Money).amount).toBe('12345.67')
    expect((transfer.destination as TransferDestinationBlockchainLocation).address).toBe('0xSECRET')
  })
})

describe('immutability', () => {
  const transfer = decodeComplete(
    '"fees":[{"amount":"1","currency":"USD","type":"network"},' +
      '{"amount":"2","currency":"EUR","type":"network"}]',
  )

  it('freezes the transfer, its fee list, each fee, and each location', () => {
    expect(Object.isFrozen(transfer)).toBe(true)
    expect(Object.isFrozen(transfer.fees)).toBe(true)
    expect(Object.isFrozen(transfer.fees[0])).toBe(true)
    expect(Object.isFrozen(transfer.source)).toBe(true)
    expect(Object.isFrozen(transfer.destination)).toBe(true)
  })

  it('refuses a write through a cast', () => {
    const mutable = transfer as unknown as Record<string, unknown>
    expect(() => {
      mutable['id'] = 'tr-forged'
    }).toThrow(TypeError)
    expect(() => {
      mutable['newField'] = 'x'
    }).toThrow(TypeError)
    expect(transfer.id).toBe('tr-1')
  })

  it('refuses a mutation of the returned fee array', () => {
    const mutable = transfer.fees as unknown[]
    expect(() => mutable.push(mutable[0])).toThrow(TypeError)
    expect(() => mutable.pop()).toThrow(TypeError)
    expect(transfer.fees).toHaveLength(2)
  })
})

describe('consumer construction', () => {
  it('does not accept a look-alike object as a transfer', () => {
    const fabricated = {
      id: 'tr-forged',
      source: { kind: 'account', accountId: 'a' },
      destination: { kind: 'account', accountId: 'b' },
      status: { kind: 'pending' },
      errorCode: null,
      transactionHash: null,
      policyEvaluation: null,
      createDate: null,
    }

    expect(fabricated instanceof Transfer).toBe(false)
    expect(decodeComplete() instanceof Transfer).toBe(true)
  })

  it('does not accept a look-alike object as a destination location class', () => {
    const fabricated = { kind: 'account', accountId: 'a', address: null, addressTag: null }
    expect(fabricated instanceof TransferDestinationAccountLocation).toBe(false)
  })
})

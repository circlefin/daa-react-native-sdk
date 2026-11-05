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
import { Transaction, TransactionBlockchainLocation } from '../models/Transaction'
import { MalformedPayloadError } from '../wire/payload'
import { toTransaction, toTransactions } from '../wire/transactionPayload'

/**
 * Decoding tests for the transaction model. These go through the real parse and
 * mapping rather than constructing a payload object directly, because the wire
 * spellings, the number handling, and the required/optional line are the things
 * under test — see the class note on `Transaction`.
 */

const REQUIRED =
  '"id":"txn-1","type":"transfer","status":"pending",' +
  '"amount":{"amount":"10.00","currency":"USD"},' +
  '"createDate":"2026-01-01T00:00:00Z","updateDate":"2026-01-02T00:00:00Z"'

function decode(body: string): Transaction {
  return toTransaction(JSON.parse(body) as unknown)
}

function decodeComplete(extra = ''): Transaction {
  return decode(`{${REQUIRED}${extra === '' ? '' : `,${extra}`}}`)
}

function transactionWith(field: string, value: string): Transaction {
  return decodeComplete(`"${field}":${value}`)
}

describe('required and optional fields', () => {
  it('rejects a response missing any guaranteed field', () => {
    const complete: Record<string, string> = {
      id: '"txn-1"',
      type: '"transfer"',
      status: '"pending"',
      amount: '{"amount":"10.00","currency":"USD"}',
      createDate: '"2026-01-01T00:00:00Z"',
      updateDate: '"2026-01-02T00:00:00Z"',
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    expect(decode(body(complete)).id).toBe('txn-1')

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decode(body(partial))).toThrow(MalformedPayloadError)
    }

    expect(() => decode('{}')).toThrow(MalformedPayloadError)
    expect(() => toTransaction(null)).toThrow(MalformedPayloadError)
    expect(() => toTransaction([])).toThrow(MalformedPayloadError)
  })

  it('rejects an explicit null on a guaranteed field', () => {
    expect(() =>
      decode(
        '{"id":null,"type":"transfer","status":"pending",' +
          '"amount":{"amount":"10.00","currency":"USD"},' +
          '"createDate":"2026-01-01T00:00:00Z","updateDate":"2026-01-02T00:00:00Z"}',
      ),
    ).toThrow(MalformedPayloadError)
  })

  it('rejects a field carried in the wrong shape', () => {
    expect(() => transactionWith('id', '{}')).toThrow(MalformedPayloadError)
    expect(() => transactionWith('id', 'true')).toThrow(MalformedPayloadError)
    expect(() => transactionWith('amount', '"nope"')).toThrow(MalformedPayloadError)
    expect(() => transactionWith('createDate', '7')).toThrow(MalformedPayloadError)
    expect(() => transactionWith('source', '"account"')).toThrow(MalformedPayloadError)
  })

  it('tolerates absent source and destination', () => {
    const transaction = decodeComplete()
    expect(transaction.source).toBeNull()
    expect(transaction.destination).toBeNull()
  })

  it('treats an explicit null source or destination as absence', () => {
    const transaction = decodeComplete('"source":null,"destination":null')
    expect(transaction.source).toBeNull()
    expect(transaction.destination).toBeNull()
  })
})

describe('closed sets and locations', () => {
  it('decodes each documented type and status', () => {
    expect(transactionWith('type', '"deposit"').type).toEqual({ kind: 'deposit' })
    expect(transactionWith('type', '"withdrawal"').type).toEqual({ kind: 'withdrawal' })
    expect(transactionWith('type', '"fx"').type).toEqual({ kind: 'fx' })
    expect(transactionWith('type', '"fee"').type).toEqual({ kind: 'fee' })
    expect(transactionWith('type', '"credit"').type).toEqual({ kind: 'credit' })
    expect(transactionWith('type', '"other"').type).toEqual({ kind: 'other' })
    expect(transactionWith('status', '"complete"').status).toEqual({ kind: 'complete' })
    expect(transactionWith('status', '"failed"').status).toEqual({ kind: 'failed' })
    expect(transactionWith('status', '"returned"').status).toEqual({ kind: 'returned' })
  })

  it('degrades an unfamiliar type or status to unrecognized without failing the row', () => {
    expect(transactionWith('type', '"rebate"').type).toEqual({
      kind: 'unrecognized',
      rawValue: 'rebate',
    })
    expect(transactionWith('status', '"settling"').status).toEqual({
      kind: 'unrecognized',
      rawValue: 'settling',
    })
  })

  it('decodes an account leg', () => {
    const transaction = decodeComplete('"source":{"type":"account","id":"1000662322"}')
    expect(transaction.source).toEqual({ kind: 'account', accountId: '1000662322' })
  })

  it('decodes a blockchain destination with a redacted address', () => {
    const transaction = decodeComplete(
      '"destination":{"type":"blockchain","chain":"ETH","address":"0xdest","addressTag":"memo"}',
    )
    expect(transaction.destination).toBeInstanceOf(TransactionBlockchainLocation)
    if (!(transaction.destination instanceof TransactionBlockchainLocation)) {
      throw new Error('expected a blockchain destination')
    }
    expect(transaction.destination.chain).toBe('ETH')
    expect(transaction.destination.address).toBe('0xdest')
    expect(transaction.destination.addressTag).toBe('memo')
  })

  it('accepts a blockchain source with only a chain', () => {
    const transaction = decodeComplete('"source":{"type":"blockchain","chain":"SOL"}')
    expect(transaction.source).toBeInstanceOf(TransactionBlockchainLocation)
    if (!(transaction.source instanceof TransactionBlockchainLocation)) {
      throw new Error('expected a blockchain source')
    }
    expect(transaction.source.chain).toBe('SOL')
    expect(transaction.source.address).toBeNull()
  })

  it('decodes wire and ach fiat legs', () => {
    const wire = decodeComplete(
      '"source":{"type":"wire","id":"3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8","name":"Bank of Example"}',
    )
    expect(wire.source).toEqual({
      kind: 'wire',
      fiatAccountId: '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
      name: 'Bank of Example',
    })

    const ach = decodeComplete(
      '"destination":{"type":"ach","id":"4f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8"}',
    )
    expect(ach.destination).toEqual({
      kind: 'ach',
      fiatAccountId: '4f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
      name: null,
    })
  })

  it('degrades an unfamiliar location type to unrecognized', () => {
    const transaction = decodeComplete('"source":{"type":"verified_blockchain","id":"addr-1"}')
    expect(transaction.source).toEqual({ kind: 'unrecognized', rawValue: 'verified_blockchain' })
  })

  it('rejects a fiat or account leg missing its id', () => {
    expect(() => decodeComplete('"source":{"type":"account"}')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"destination":{"type":"wire","name":"Bank"}')).toThrow(
      MalformedPayloadError,
    )
  })

  it('ignores unknown response fields wherever they appear', () => {
    const transaction = decode(
      '{"id":"txn-1","type":"transfer","status":"pending",' +
        '"amount":{"amount":"1","currency":"USD","futureScale":"2"},' +
        '"source":{"type":"account","id":"acct-src","futureField":true},' +
        '"createDate":"2026-01-01T00:00:00Z","updateDate":"2026-01-02T00:00:00Z",' +
        '"settlementTier":"gold"}',
    )
    expect(transaction.id).toBe('txn-1')
    expect(transaction.source).toEqual({ kind: 'account', accountId: 'acct-src' })
    expect(Object.keys(transaction)).not.toContain('settlementTier')
  })
})

describe('list decoding', () => {
  it('decodes an array of transactions and freezes it', () => {
    const items = toTransactions([JSON.parse(`{${REQUIRED}}`)])
    expect(items).toHaveLength(1)
    expect(items[0]?.id).toBe('txn-1')
    expect(Object.isFrozen(items)).toBe(true)
  })

  it('rejects a non-array collection payload', () => {
    expect(() => toTransactions({})).toThrow(MalformedPayloadError)
    expect(() => toTransactions(null)).toThrow(MalformedPayloadError)
  })
})

describe('redaction', () => {
  const transaction = decodeComplete(
    '"destination":{"type":"blockchain","chain":"ETH","address":"0xSECRET","addressTag":"tag-SECRET"}',
  )
  const secrets = ['0xSECRET', 'tag-SECRET', '10.00']

  it('keeps every sensitive value off the transaction object as an own property', () => {
    expect(Object.getOwnPropertyNames(transaction).sort()).toEqual(
      ['id', 'type', 'status', 'source', 'destination', 'createDate', 'updateDate'].sort(),
    )
    expect(Object.getOwnPropertyNames(transaction.destination as object).sort()).toEqual(
      ['kind', 'chain'].sort(),
    )
  })

  it.each([
    ['JSON.stringify', (value: unknown): string => JSON.stringify(value) ?? ''],
    ['util.inspect (what console.log renders)', (value: unknown): string => inspect(value)],
    ['String()', (value: unknown): string => String(value)],
    [
      'spread into a plain object',
      (value: unknown): string => JSON.stringify({ ...(value as object) }) ?? '',
    ],
  ])('reveals no sensitive value through %s', (_name, render) => {
    for (const rendered of [render(transaction), render(transaction.destination)]) {
      for (const secret of secrets) {
        expect(rendered).not.toContain(secret)
      }
    }
  })

  it('redacts amount and blockchain address in toJSON', () => {
    expect(JSON.parse(JSON.stringify(transaction))).toMatchObject({
      id: 'txn-1',
      amount: { amount: '<redacted>', currency: 'USD' },
      destination: {
        kind: 'blockchain',
        chain: 'ETH',
        address: '<redacted>',
        addressTag: '<redacted>',
      },
    })
  })

  it('still reveals hidden fields when inspect is asked to', () => {
    const revealing = inspect(transaction, { showHidden: true, getters: true, depth: null })
    expect(revealing).toContain('10.00')
    expect(revealing).toContain('0xSECRET')
  })
})

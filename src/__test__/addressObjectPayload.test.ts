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
import * as sdk from '../index'
import { AddressObject } from '../models/AddressObject'
import { toAddressObject } from '../wire/addressObjectPayload'
import { MalformedPayloadError } from '../wire/payload'

/**
 * Decoding tests for the deposit-address model.
 *
 * These go through the real parse and mapping rather than constructing a
 * payload object directly, because the wire spellings and the
 * required/optional line are what is under test.
 */

/** The fields every custody source guarantees on a by-id read. */
const REQUIRED = '"id":"addr-1","address":"0xRECEIVE","chain":"ETH"'

function decode(body: string): AddressObject {
  return toAddressObject(JSON.parse(body) as unknown)
}

function decodeComplete(extra = ''): AddressObject {
  return decode(`{${REQUIRED}${extra === '' ? '' : `,${extra}`}}`)
}

function addressWith(field: string, value: string): AddressObject {
  return decodeComplete(`"${field}":${value}`)
}

describe('required and optional fields', () => {
  /**
   * A response missing something every custody source guarantees is
   * malformed, not an address with a hole in it.
   */
  it('rejects a response missing any guaranteed field', () => {
    const complete: Record<string, string> = {
      id: '"addr-1"',
      address: '"0xRECEIVE"',
      chain: '"ETH"',
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    // Sanity: the complete body decodes, or every assertion below is vacuous.
    expect(decode(body(complete)).id).toBe('addr-1')

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decode(body(partial))).toThrow(MalformedPayloadError)
    }

    expect(() => decode('{}')).toThrow(MalformedPayloadError)
    expect(() => toAddressObject(null)).toThrow(MalformedPayloadError)
    expect(() => toAddressObject([])).toThrow(MalformedPayloadError)
  })

  /** An explicit `null` on a guaranteed field is the same defect as omitting it. */
  it('rejects an explicit null on a guaranteed field', () => {
    expect(() => decode('{"id":null,"address":"0xRECEIVE","chain":"ETH"}')).toThrow(
      MalformedPayloadError,
    )
  })

  /** A present field in a shape the contract does not describe is malformed, not coerced. */
  it('rejects a field carried in the wrong shape', () => {
    expect(() => addressWith('id', '{}')).toThrow(MalformedPayloadError)
    expect(() => addressWith('id', 'true')).toThrow(MalformedPayloadError)
    expect(() => addressWith('address', '7')).toThrow(MalformedPayloadError)
    expect(() => addressWith('addressTag', '[]')).toThrow(MalformedPayloadError)
    expect(() => addressWith('currency', '7')).toThrow(MalformedPayloadError)
    expect(() => addressWith('accountId', '{}')).toThrow(MalformedPayloadError)
    expect(() => addressWith('chain', '9')).toThrow(MalformedPayloadError)
  })

  /**
   * `currency` is absent on segregated and self-custody by-id reads and
   * present on `create`. A model that required it would fail to decode most
   * segregated and self-custody address reads.
   */
  it('tolerates an address with no currency', () => {
    expect(decodeComplete().currency).toBeNull()
    expect(addressWith('currency', '"USD"').currency).toBe('USD')
  })

  /** `accountId` is null when an omnibus address cannot be attributed to an account. */
  it('carries accountId including a null one for an unattributed omnibus address', () => {
    expect(addressWith('accountId', '"acct-1"').accountId).toBe('acct-1')
    expect(decodeComplete().accountId).toBeNull()
  })

  /** `addressTag` is present only on omnibus addresses; segregated and self-custody have none. */
  it('carries addressTag including a null one', () => {
    expect(addressWith('addressTag', '"MEMO123"').addressTag).toBe('MEMO123')
    expect(decodeComplete().addressTag).toBeNull()
  })
})

describe('chain and currency are plain strings, not closed unions', () => {
  /**
   * The service adds chains and currencies independently of an SDK release —
   * the same reason `Account.blockchain` and `Money.currency` are plain
   * strings. A chain or
   * currency this version has never heard of must still decode.
   */
  it('carries a chain this version has never heard of', () => {
    expect(addressWith('chain', '"SOME_NEW_CHAIN"').chain).toBe('SOME_NEW_CHAIN')
  })

  it('carries a currency this version has never heard of', () => {
    expect(addressWith('currency', '"SOME_NEW_CURRENCY"').currency).toBe('SOME_NEW_CURRENCY')
  })
})

describe('forward compatibility', () => {
  /**
   * Forward-compatible decoding: an unknown response field
   * must not fail the read, matching the service's own tolerance for unknown
   * fields.
   */
  it('ignores an unknown response field wherever it appears', () => {
    const address = decode(
      '{"id":"addr-1","address":"0xRECEIVE","chain":"ETH","riskScore":7,"flags":null,' +
        '"metadata":{"nested":true}}',
    )

    expect(address.id).toBe('addr-1')
    expect(address.chain).toBe('ETH')
    expect(Object.keys(address)).not.toContain('riskScore')
    expect(Object.keys(address)).not.toContain('metadata')
  })
})

describe('redaction', () => {
  const address = decodeComplete('"addressTag":"MEMO-SECRET","currency":"USD","accountId":"acct-1"')
  const secrets = ['0xRECEIVE', 'MEMO-SECRET']

  /**
   * There is no `toString` hook every JavaScript rendering path goes through,
   * so redaction is held by **absence**: `address` and `addressTag` are
   * reached only through a prototype accessor over a `#` private field, never
   * an own property, so `Object.keys`, `JSON.stringify`, spread, `for...in`,
   * and the inspectors behind `console.log` cannot reach them.
   */
  it('keeps the address and its tag off the object as an own property', () => {
    expect(Object.getOwnPropertyNames(address).sort()).toEqual(
      ['id', 'currency', 'chain', 'accountId'].sort(),
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
    const rendered = render(address)
    for (const secret of secrets) {
      expect(rendered).not.toContain(secret)
    }
  })

  it('still renders the identifiers and states that make a log line useful', () => {
    expect(String(address)).toContain('addr-1')
    expect(String(address)).toContain('ETH')
    expect(JSON.stringify(address)).toContain('addr-1')
    expect(inspect(address)).toContain('addr-1')
  })

  it('says the address and its tag were withheld rather than omitting them silently', () => {
    expect(String(address)).toContain('address=<redacted>')
    expect(String(address)).toContain('addressTag=<redacted>')
    expect(JSON.parse(JSON.stringify(address))).toMatchObject({
      address: '<redacted>',
      addressTag: '<redacted>',
    })
  })

  /** There is nothing to redact from an address with no tag, so it renders `null`, not a marker. */
  it('renders a null addressTag as null rather than a redaction marker', () => {
    const noTag = decodeComplete()
    expect(JSON.parse(JSON.stringify(noTag))).toMatchObject({ addressTag: null })
    expect(String(noTag)).toContain('addressTag=null')
  })

  /**
   * **The honest limit, recorded rather than claimed away.** What is prevented
   * is a value reaching a log by *accident*. `util.inspect(value, { showHidden:
   * true, getters: true })` walks and calls prototype accessors deliberately,
   * and reveals every field — the same limit `accountPayload.test.ts` pins for
   * `Account`.
   */
  it('does not withhold from an inspector explicitly asked to evaluate accessors', () => {
    const revealing = inspect(address, { showHidden: true, getters: true, depth: null })
    expect(revealing).toContain('0xRECEIVE')
    expect(revealing).toContain('MEMO-SECRET')

    // The ordinary route, and it is the public read the model exists to provide.
    expect(address.address).toBe('0xRECEIVE')
    expect(address.addressTag).toBe('MEMO-SECRET')
  })
})

describe('immutability', () => {
  const address = decodeComplete()

  /** `readonly` is erased at compile time; freezing at construction is what actually holds this. */
  it('freezes the address object', () => {
    expect(Object.isFrozen(address)).toBe(true)
  })

  it('refuses a write through a cast', () => {
    const mutable = address as unknown as Record<string, unknown>
    expect(() => {
      mutable['id'] = 'addr-forged'
    }).toThrow(TypeError)
    expect(() => {
      mutable['newField'] = 'x'
    }).toThrow(TypeError)
    expect(address.id).toBe('addr-1')
  })
})

describe('consumer construction', () => {
  /**
   * No runtime constructor for this model reaches the public entry. The model is
   * exported as a type only, matching the guarantee for `Account`.
   */
  it('exposes no model constructor on the public entry', () => {
    const runtime = sdk as unknown as Record<string, unknown>
    expect(runtime['AddressObject']).toBeUndefined()
  })

  /**
   * The `#` private fields mean an object shaped like an address is not one,
   * so a fabricated value cannot be passed to code that checks.
   */
  it('does not accept a look-alike object as an address object', () => {
    const fabricated = {
      id: 'addr-forged',
      address: '0xattacker',
      addressTag: null,
      currency: null,
      chain: 'ETH',
      accountId: null,
    }

    expect(fabricated instanceof AddressObject).toBe(false)
    expect(decodeComplete() instanceof AddressObject).toBe(true)
  })
})

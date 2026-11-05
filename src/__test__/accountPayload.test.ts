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
import { Account } from '../models/Account'
import type { Money } from '../models/Money'
import { toAccount } from '../wire/accountPayload'
import { MalformedPayloadError } from '../wire/payload'

/**
 * Decoding tests for the account model.
 *
 * These go through the real parse and mapping rather than constructing a payload
 * object directly, because the wire spellings, the number handling, and the
 * required/optional line are the things under test.
 */

/** The fields the service guarantees, so a test about one optional field is not also a test about a missing required one. */
const REQUIRED =
  '"accountId":"acct-1","balances":[],"entityId":"e",' +
  '"purpose":"custody","status":"active","type":"first_party"'

function decode(body: string): Account {
  return toAccount(JSON.parse(body) as unknown)
}

function decodeComplete(extra = ''): Account {
  return decode(`{${REQUIRED}${extra === '' ? '' : `,${extra}`}}`)
}

function accountWith(field: string, value: string): Account {
  return decodeComplete(`"${field}":${value}`)
}

describe('closed-set fields', () => {
  it('maps every known custody type and falls back for the rest', () => {
    expect(accountWith('custodyType', '"omnibus"').custodyType).toEqual({ kind: 'omnibus' })
    expect(accountWith('custodyType', '"segregated"').custodyType).toEqual({ kind: 'segregated' })
    expect(accountWith('custodyType', '"self"').custodyType).toEqual({ kind: 'self' })
    // A value the service adds later must read as unrecognized rather than
    // failing the whole account — and must keep the string, which is the
    // difference between support being able to answer "why did this read as
    // unknown" and not.
    expect(accountWith('custodyType', '"mpc"').custodyType).toEqual({
      kind: 'unrecognized',
      rawValue: 'mpc',
    })
  })

  it('maps every known purpose, status and party type', () => {
    expect(accountWith('purpose', '"custody"').purpose).toEqual({ kind: 'custody' })
    expect(accountWith('purpose', '"payments"').purpose).toEqual({ kind: 'payments' })
    expect(accountWith('status', '"active"').status).toEqual({ kind: 'active' })
    expect(accountWith('status', '"pending"').status).toEqual({ kind: 'pending' })
    expect(accountWith('status', '"rejected"').status).toEqual({ kind: 'rejected' })
    expect(accountWith('status', '"archived"').status).toEqual({ kind: 'archived' })
    expect(accountWith('type', '"first_party"').type).toEqual({ kind: 'first_party' })
    expect(accountWith('type', '"third_party"').type).toEqual({ kind: 'third_party' })
  })

  /**
   * The contract requires an unrecognised value be preserved "as an unknown/raw-value
   * case instead of failing the entire response". Not failing is half of it; a bare
   * marker satisfies that half and silently discards what the service sent.
   */
  it('keeps the string the service sent on every closed-set field', () => {
    const account = decode(
      '{"accountId":"acct-1","balances":[],"entityId":"e",' +
        '"custodyType":"mpc","purpose":"treasury","status":"frozen","type":"fourth_party"}',
    )

    expect(account.custodyType).toEqual({ kind: 'unrecognized', rawValue: 'mpc' })
    expect(account.purpose).toEqual({ kind: 'unrecognized', rawValue: 'treasury' })
    expect(account.status).toEqual({ kind: 'unrecognized', rawValue: 'frozen' })
    expect(account.type).toEqual({ kind: 'unrecognized', rawValue: 'fourth_party' })
  })

  /**
   * `custodyType` is outside the guaranteed set, so it is the one closed-set field
   * whose absence is tolerated, and the only way to reach a null raw value. An
   * absent `purpose`, `status`, or `type` is a missing required value.
   */
  it('tolerates an absent custody type with a null raw value', () => {
    expect(decodeComplete().custodyType).toEqual({ kind: 'unrecognized', rawValue: null })
  })

  /**
   * The wire spellings are lower snake_case; none of the multi-word `kind` values
   * matches its own wire value's casing, so nothing would catch a mapper written
   * from the public type instead of from the wire.
   */
  it('does not accept a public kind spelling as a wire value', () => {
    expect(accountWith('type', '"firstParty"').type).toEqual({
      kind: 'unrecognized',
      rawValue: 'firstParty',
    })
    expect(accountWith('custodyType', '"SELF"').custodyType).toEqual({
      kind: 'unrecognized',
      rawValue: 'SELF',
    })
  })

  /**
   * A JavaScript hazard with no Kotlin or Swift equivalent: an object literal used
   * as a lookup table inherits from `Object.prototype`, so `table['constructor']`
   * returns a function rather than `undefined` and a value spelled like a
   * prototype member would be "recognised" as something that is not a custody type
   * at all.
   */
  it('treats a value spelled like an Object.prototype member as unrecognized', () => {
    for (const hostile of ['constructor', 'toString', 'hasOwnProperty', '__proto__']) {
      expect(accountWith('custodyType', `"${hostile}"`).custodyType).toEqual({
        kind: 'unrecognized',
        rawValue: hostile,
      })
      expect(accountWith('status', `"${hostile}"`).status).toEqual({
        kind: 'unrecognized',
        rawValue: hostile,
      })
    }
  })
})

describe('required and optional fields', () => {
  /**
   * A response missing something the service guarantees is malformed, not an
   * account with holes in it. Accepting it would turn a service defect into an SDK
   * success and push the null handling onto every caller.
   */
  it('rejects a response missing any guaranteed field', () => {
    const complete: Record<string, string> = {
      accountId: '"acct-1"',
      balances: '[]',
      entityId: '"e"',
      purpose: '"custody"',
      status: '"active"',
      type: '"first_party"',
    }
    const body = (fields: Record<string, string>): string =>
      `{${Object.entries(fields)
        .map(([k, v]) => `"${k}":${v}`)
        .join(',')}}`

    // Sanity: the complete body decodes, or every assertion below is vacuous.
    expect(decode(body(complete)).accountId).toBe('acct-1')

    for (const omitted of Object.keys(complete)) {
      const partial = { ...complete }
      delete partial[omitted]
      expect(() => decode(body(partial))).toThrow(MalformedPayloadError)
    }

    // The degenerate case, and a non-object payload.
    expect(() => decode('{}')).toThrow(MalformedPayloadError)
    expect(() => toAccount(null)).toThrow(MalformedPayloadError)
    expect(() => toAccount([])).toThrow(MalformedPayloadError)
  })

  /** An explicit `null` on a guaranteed field is the same defect as omitting it. */
  it('rejects an explicit null on a guaranteed field', () => {
    expect(() =>
      decode(
        '{"accountId":null,"balances":[],"entityId":"e","purpose":"custody","status":"active","type":"first_party"}',
      ),
    ).toThrow(MalformedPayloadError)
  })

  /** A present field in a shape the contract does not describe is malformed, not coerced. */
  it('rejects a field carried in the wrong shape', () => {
    expect(() => accountWith('accountId', '{}')).toThrow(MalformedPayloadError)
    expect(() => accountWith('accountId', 'true')).toThrow(MalformedPayloadError)
    expect(() => accountWith('description', 'true')).toThrow(MalformedPayloadError)
    expect(() => accountWith('description', '[]')).toThrow(MalformedPayloadError)
    expect(() => accountWith('balances', '{}')).toThrow(MalformedPayloadError)
    expect(() => accountWith('businessPii', '"nope"')).toThrow(MalformedPayloadError)
  })

  /**
   * A JSON **number** in a field the contract types as a string is a shape error,
   * not a value to coerce.
   *
   * The decoder reads the parsed JSON as-is, with no pre-parse pass that quotes
   * number literals (the service sends `Money.amount` as a JSON string), so a
   * JSON number and a genuine string stay distinguishable.
   */
  it('rejects a JSON number in a field the contract types as a string', () => {
    expect(() => accountWith('description', '7')).toThrow(MalformedPayloadError)
    expect(() => accountWith('accountId', '7')).toThrow(MalformedPayloadError)
  })

  /**
   * `amount` in particular. `JSON.parse` would already have rounded a JSON number
   * to an IEEE-754 double before this code saw the token, so there would be no
   * exact value left to report — and reporting a rounded balance as though the
   * service had sent it is the one thing this decoder must not do. The service
   * sends the field as a string, so this shape should never arrive.
   */
  it('rejects a balance amount sent as a JSON number rather than coercing it', () => {
    expect(() => decodeComplete('"balances":[{"amount":10.5,"currency":"USD"}]')).toThrow(
      MalformedPayloadError,
    )
    expect(() =>
      decodeComplete('"balances":[{"amount":1234567890123456.78,"currency":"USD"}]'),
    ).toThrow(MalformedPayloadError)
  })

  /**
   * `description` is absent on real accounts — the service treats it as
   * nullable, and accounts can be created with none — so requiring it would
   * fail an ordinary read. Trusting the OpenAPI's `required:` block here would
   * be a defect.
   */
  it('tolerates an account with no description', () => {
    expect(decodeComplete().description).toBeNull()
    expect(accountWith('description', '"labelled"').description).toBe('labelled')
  })

  it('reports every other absent optional field as absent', () => {
    const account = decodeComplete()
    expect(account.blockchain).toBeNull()
    expect(account.clientEntityId).toBeNull()
    expect(account.depositAddress).toBeNull()
    expect(account.groupId).toBeNull()
    expect(account.businessPii).toBeNull()
  })
})

describe('balances', () => {
  /**
   * The service sends `amount` as a JSON string holding a decimal literal.
   * Converting it to a JavaScript number would round this value; carrying the
   * string as sent does not.
   */
  it('preserves an amount that a JavaScript number would round', () => {
    const account = decodeComplete('"balances":[{"amount":"1234567890123456.78","currency":"USD"}]')

    expect(account.balances).toHaveLength(1)
    expect((account.balances[0] as Money).amount).toBe('1234567890123456.78')
    expect((account.balances[0] as Money).currency).toBe('USD')
  })

  /** Scale survives, because a caller rendering `1.50` must not be handed `1.5`. */
  it('preserves the scale the service sent', () => {
    const account = decodeComplete('"balances":[{"amount":"1.50","currency":"USD"}]')
    expect((account.balances[0] as Money).amount).toBe('1.50')
  })

  /**
   * `Money.currency` is typed in the OpenAPI as a closed enum of twenty-two
   * currencies that omits USD. Carrying it as a string is the whole point — the
   * balance this SDK exists to report must survive.
   */
  it('accepts a currency the schema enum does not list', () => {
    for (const currency of ['USD', 'EURC', 'SOME_NEW_TOKEN']) {
      const account = decodeComplete(`"balances":[{"amount":"1","currency":"${currency}"}]`)
      expect((account.balances[0] as Money).currency).toBe(currency)
    }
  })

  /** An unreadable balance is malformed too — the contract guarantees both money fields. */
  it('rejects a balance whose amount or currency cannot be read', () => {
    expect(() => decodeComplete('"balances":[{"amount":"not-a-number","currency":"USD"}]')).toThrow(
      MalformedPayloadError,
    )
    expect(() => decodeComplete('"balances":[{"currency":"USD"}]')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"balances":[{"amount":"1"}]')).toThrow(MalformedPayloadError)
    expect(() => decodeComplete('"balances":["1.00"]')).toThrow(MalformedPayloadError)
  })

  /**
   * The number grammar is the *only* thing standing between a string field and a
   * caller's decimal library, so its edges are worth pinning. Each of these is a
   * shape a hand-rolled or lenient check tends to wave through: JavaScript's own
   * `Number()` accepts every one of them, and `parseFloat` truncates the rest to a
   * prefix. A caller that trusted `amount` to be a number would then get `NaN`,
   * `Infinity`, or a silently different value out of its decimal library.
   */
  it('rejects text that is not an RFC 8259 number', () => {
    const notNumbers = [
      '', // absent-but-present
      ' 1', // leading space
      '1 ', // trailing space
      '+1', // JSON has no unary plus
      '01', // leading zero
      '-01',
      '.5', // no integer part
      '1.', // trailing decimal point
      '1..2',
      '1e', // truncated exponent
      '1e+',
      '0x10', // hex
      '1_000', // digit separator
      'Infinity',
      '-Infinity',
      'NaN',
      '1,50', // decimal comma
      '1.5.5',
      '--1',
      '1e1.5', // fractional exponent
    ]

    for (const amount of notNumbers) {
      expect(() =>
        decodeComplete(`"balances":[{"amount":${JSON.stringify(amount)},"currency":"USD"}]`),
      ).toThrow(MalformedPayloadError)
    }
  })

  /** The other side of the same line: every shape the grammar does allow. */
  it('accepts the number shapes the grammar allows', () => {
    const numbers = [
      '0',
      '-0',
      '1',
      '-1',
      '0.0',
      '1.50',
      '-0.01',
      '1e10',
      '1E10',
      '1e+10',
      '1e-10',
      '0.5e-3',
    ]

    for (const amount of numbers) {
      const account = decodeComplete(`"balances":[{"amount":"${amount}","currency":"USD"}]`)
      expect((account.balances[0] as Money).amount).toBe(amount)
    }
  })

  it('decodes an empty balance list as an empty list', () => {
    expect(decodeComplete().balances).toEqual([])
  })
})

describe('forward compatibility', () => {
  /**
   * Forward-compatible decoding of an unknown
   * response field, alongside the unknown closed-set value covered above. The
   * pairing is the point — the service adding a field and the service adding an
   * enum value are the two ways a response outruns a shipped SDK, and neither
   * may fail the read.
   *
   * Unknown *fields* are the half with no other test. A mapper that validated
   * the key set instead of reading the keys it knows would pass every other test
   * in this file and still break every consumer the day a field is added.
   */
  it('ignores an unknown response field wherever it appears', () => {
    const account = decode(
      '{"accountId":"acct-1","entityId":"e","purpose":"custody","status":"active",' +
        '"type":"first_party","settlementTier":"gold","riskScore":7,"flags":null,' +
        '"balances":[{"amount":"1.00","currency":"USD","provisionalAmount":"0.25"}],' +
        '"businessPii":{"businessName":"Acme","taxRegime":{"nested":true}}}',
    )

    // The known fields still decode, and the unknown ones are simply absent.
    expect(account.accountId).toBe('acct-1')
    expect(account.balances).toHaveLength(1)
    expect((account.balances[0] as Money).amount).toBe('1.00')
    expect(Object.keys(account)).not.toContain('settlementTier')
    expect(Object.keys(account)).not.toContain('riskScore')
  })

  /**
   * The other half of the requirement, asserted together with the first so the
   * pair cannot drift apart: an unrecognised value and an unrecognised field in
   * the same response still yield a readable account.
   */
  it('decodes a response carrying an unknown field and an unknown value at once', () => {
    const account = decode(
      '{"accountId":"acct-1","balances":[],"entityId":"e","purpose":"custody",' +
        '"status":"settling","type":"first_party","tierMetadata":{"a":1}}',
    )

    expect(account.accountId).toBe('acct-1')
    expect(account.status).toEqual({ kind: 'unrecognized', rawValue: 'settling' })
  })
})

describe('fields the OpenAPI omits', () => {
  /**
   * `blockchain` is the account's immutable home chain, a plain string because new
   * chains ship without an SDK release.
   */
  it('carries the home chain including one this version has never heard of', () => {
    expect(accountWith('blockchain', '"ETH"').blockchain).toBe('ETH')
    expect(accountWith('blockchain', '"SOME_NEW_CHAIN"').blockchain).toBe('SOME_NEW_CHAIN')
    // Absent is reported as absent. The contract says DAA provisions on ARC when
    // the field is omitted at creation, but that is the service's default to
    // apply — inventing it here would report a home chain the service never sent.
    expect(decodeComplete().blockchain).toBeNull()
  })

  /** The receive address a self-custody consumer needs must survive decoding. */
  it('carries the deposit address', () => {
    expect(accountWith('depositAddress', '"0xabc"').depositAddress).toBe('0xabc')
    // Absent until the provider mapping is complete — a state, not an error.
    expect(decodeComplete().depositAddress).toBeNull()
  })

  it('carries business identity enrichment', () => {
    const account = decodeComplete(
      '"businessPii":{"address":{"city":"Boston","country":"US","line1":"1 Main St",' +
        '"line2":"Apt 2","district":"MA","postalCode":"02101"},' +
        '"businessName":"Acme Inc","businessUniqueIdentifier":"EIN-123",' +
        '"identifierIssuingCountryCode":"US"}',
    )

    const pii = account.businessPii
    expect(pii?.businessName).toBe('Acme Inc')
    expect(pii?.businessUniqueIdentifier).toBe('EIN-123')
    expect(pii?.identifierIssuingCountryCode).toBe('US')
    expect(pii?.address?.city).toBe('Boston')
    expect(pii?.address?.country).toBe('US')
    expect(pii?.address?.district).toBe('MA')
    expect(pii?.address?.line1).toBe('1 Main St')
    expect(pii?.address?.line2).toBe('Apt 2')
    expect(pii?.address?.postalCode).toBe('02101')
  })

  /**
   * A partial one is ordinary, not malformed. The service populates these
   * best-effort from customer records and omits what it does not have, so a
   * business with no tax id on file must still yield a readable account.
   */
  it('tolerates partial business identity enrichment', () => {
    const pii = decodeComplete('"businessPii":{"businessName":"Acme Inc"}').businessPii

    expect(pii?.businessName).toBe('Acme Inc')
    expect(pii?.businessUniqueIdentifier).toBeNull()
    expect(pii?.identifierIssuingCountryCode).toBeNull()
    expect(pii?.address).toBeNull()
  })
})

describe('redaction', () => {
  const account = decodeComplete(
    '"depositAddress":"0xSECRET","balances":[{"amount":"12345.67","currency":"USD"}],' +
      '"businessPii":{"address":{"city":"Boston","line1":"1 Main St"},"businessName":"Acme Inc",' +
      '"businessUniqueIdentifier":"EIN-123"}',
  )
  const secrets = ['0xSECRET', '12345.67', 'Acme Inc', 'EIN-123', '1 Main St', 'Boston']

  /**
   * There is no `toString` hook that JavaScript's rendering paths all go through,
   * so redaction is held by **absence**: every sensitive value is reached through a
   * prototype accessor over a `#` private field rather than through an own
   * property. `Object.keys`, `JSON.stringify`, spread, `for...in`, and the
   * inspectors behind `console.log` all walk own enumerable properties, so none of
   * them can reach one.
   */
  it('keeps every sensitive value off the account object as an own property', () => {
    expect(Object.getOwnPropertyNames(account).sort()).toEqual(
      [
        'accountId',
        'blockchain',
        'clientEntityId',
        'custodyType',
        'description',
        'entityId',
        'groupId',
        'purpose',
        'status',
        'type',
      ].sort(),
    )
    expect(Object.getOwnPropertyNames(account.balances[0] as Money)).toEqual(['currency'])
    expect(Object.getOwnPropertyNames(account.businessPii ?? {})).toEqual([])
    expect(Object.getOwnPropertyNames(account.businessPii?.address ?? {})).toEqual([])
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
      render(account),
      render(account.balances),
      render(account.balances[0]),
      render(account.businessPii),
      render(account.businessPii?.address),
    ]) {
      for (const secret of secrets) {
        expect(rendered).not.toContain(secret)
      }
    }
  })

  it('still renders the identifiers and states that make a log line useful', () => {
    expect(String(account)).toContain('acct-1')
    expect(String(account)).toContain('active')
    expect(JSON.stringify(account)).toContain('acct-1')
    expect(inspect(account)).toContain('acct-1')
  })

  /** The balance *count* is what stands in for the balances, as on the other SDKs. */
  it('renders a balance count in place of the balances', () => {
    expect(String(account)).toContain('balances=1 entries')
    expect(JSON.parse(JSON.stringify(account))).toMatchObject({ balances: '1 entries' })
  })

  it('says the amount was withheld rather than omitting it silently', () => {
    expect(String(account.balances[0])).toBe('Money(amount=<redacted>, currency=USD)')
    expect(JSON.parse(JSON.stringify(account.balances[0]))).toEqual({
      amount: '<redacted>',
      currency: 'USD',
    })
    expect(JSON.parse(JSON.stringify(account.businessPii))).toBe('BusinessPii(<redacted>)')
    expect(JSON.parse(JSON.stringify(account.businessPii?.address))).toBe('Address(<redacted>)')
  })

  /**
   * **The honest limit, recorded rather than claimed away.** What is prevented is a
   * value reaching a log by *accident* — the crash reporter, the
   * `console.log(account)`, the `JSON.stringify` of a state tree. A consumer that
   * reads `account.balances[0].amount` and logs it is doing so deliberately, and
   * nothing in an SDK that has to expose the balance can stop that.
   *
   * Nor is it a control against an inspector that is *asked* to evaluate prototype
   * accessors: `util.inspect(value, { showHidden: true, getters: true })` walks and
   * calls them, and reveals every field. That combination is a debugger's opt-in,
   * not something `console.log` or a crash reporter does, but the claim this SDK
   * makes is "not in a default rendering" and not "unreachable".
   */
  it('does not withhold from an inspector explicitly asked to evaluate accessors', () => {
    const revealing = inspect(account, { showHidden: true, getters: true, depth: null })
    expect(revealing).toContain('12345.67')
    expect(revealing).toContain('0xSECRET')

    // The ordinary route, and it is the public read the model exists to provide.
    expect((account.balances[0] as Money).amount).toBe('12345.67')
  })
})

describe('immutability', () => {
  const account = decodeComplete(
    '"balances":[{"amount":"1","currency":"USD"},{"amount":"2","currency":"EUR"}]',
  )

  /**
   * `readonly` is erased at compile time, so it is not what holds this. The
   * instance and the balance array are frozen at construction, which is the
   * runtime equivalent of the `unmodifiableList` the Kotlin model needs.
   */
  it('freezes the account, its balances, and each balance', () => {
    expect(Object.isFrozen(account)).toBe(true)
    expect(Object.isFrozen(account.balances)).toBe(true)
    expect(Object.isFrozen(account.balances[0])).toBe(true)
  })

  it('refuses a write through a cast', () => {
    const mutable = account as unknown as Record<string, unknown>
    expect(() => {
      mutable['accountId'] = 'acct-forged'
    }).toThrow(TypeError)
    expect(() => {
      mutable['balances'] = []
    }).toThrow(TypeError)
    expect(() => {
      mutable['newField'] = 'x'
    }).toThrow(TypeError)
    expect(account.accountId).toBe('acct-1')
    expect(account.balances).toHaveLength(2)
  })

  it('refuses a mutation of the returned balance array', () => {
    const mutable = account.balances as Money[]
    expect(() => mutable.push(mutable[0] as Money)).toThrow(TypeError)
    expect(() => mutable.pop()).toThrow(TypeError)
    expect(account.balances).toHaveLength(2)
  })
})

describe('consumer construction', () => {
  /**
   * The control is that no runtime constructor for a model reaches the public
   * entry, and neither does the factory that builds one. A consumer resolving the
   * package gets types and nothing to call.
   */
  it('exposes no model constructor on the public entry', () => {
    const runtime = sdk as unknown as Record<string, unknown>
    for (const name of [
      'Account',
      'Money',
      'BusinessPii',
      'Address',
      'AccountsClient',
      'DaaUserClient',
      'createDaaUserClient',
      'toAccount',
      'decodeDataEnvelope',
    ]) {
      expect(runtime[name]).toBeUndefined()
    }
  })

  /**
   * And the type is nominal, not structural: the `#` private fields mean an object
   * shaped like an account is not one, so a fabricated value cannot be passed to
   * code that checks. TypeScript rejects the same literal at compile time for the
   * same reason.
   */
  it('does not accept a look-alike object as an account', () => {
    const fabricated = {
      accountId: 'acct-forged',
      balances: [],
      blockchain: null,
      businessPii: null,
      clientEntityId: null,
      custodyType: { kind: 'self' },
      depositAddress: '0xattacker',
      description: null,
      entityId: 'e',
      groupId: null,
      purpose: { kind: 'custody' },
      status: { kind: 'active' },
      type: { kind: 'first_party' },
    }

    expect(fabricated instanceof Account).toBe(false)
    expect(decodeComplete() instanceof Account).toBe(true)
  })
})

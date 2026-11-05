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

import { toWire, toWireInstruction, toWireSummaries, toWireSummary } from '../wire/wirePayload'

const COMPLETE_WIRE = {
  id: 'a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd',
  type: 'wire',
  status: 'complete',
  description: 'WELLS FARGO BANK, NA ****0010',
  trackingRef: 'CIR1A2B3C4',
  fingerprint: 'eb170539-9e1c-4e92-bf4f-1d09534fdca2',
  billingDetails: {
    name: 'Satoshi Nakamoto',
    city: 'Boston',
    country: 'US',
    line1: '100 Money Street',
    postalCode: '01234',
  },
  createDate: '2026-01-01T00:00:00Z',
  updateDate: '2026-01-02T00:00:00Z',
}

function decodeSummary(extra: Record<string, unknown> = {}) {
  return toWireSummary({ ...COMPLETE_WIRE, ...extra })
}

function decodeWire(extra: Record<string, unknown> = {}) {
  return toWire({ ...COMPLETE_WIRE, ...extra })
}

describe('wire summary payload', () => {
  it('decodes the guaranteed core and defaults every absent enrichment', () => {
    const wire = decodeSummary()

    expect(wire.id).toBe(COMPLETE_WIRE.id)
    expect(wire.type).toBe('wire')
    expect(wire.status).toEqual({ kind: 'complete' })
    expect(wire.description).toBe(COMPLETE_WIRE.description)
    expect(wire.trackingRef).toBe(COMPLETE_WIRE.trackingRef)
    expect(wire.fingerprint).toBe(COMPLETE_WIRE.fingerprint)
    expect(wire.billingDetails.name).toBe('Satoshi Nakamoto')
    expect(wire.bankAddress).toBeNull()
    expect(wire.virtualAccountEnabled).toBeNull()
    expect(wire.ffcMemo).toBeNull()
    expect(wire.updateDate).toBe(COMPLETE_WIRE.updateDate)
  })

  it('rejects a wire missing a guaranteed field', () => {
    const partial: Record<string, unknown> = { ...COMPLETE_WIRE }
    delete partial.billingDetails
    expect(() => toWireSummary(partial)).toThrow()
  })

  it('decodes bank address, virtual-account flag, and ffcMemo when present', () => {
    const wire = decodeSummary({
      bankAddress: { country: 'US', bankName: 'WELLS FARGO', city: 'SAN FRANCISCO' },
      virtualAccountEnabled: true,
      ffcMemo: 'FFC for Jane Doe',
    })

    expect(wire.bankAddress?.country).toBe('US')
    expect(wire.bankAddress?.bankName).toBe('WELLS FARGO')
    expect(wire.virtualAccountEnabled).toBe(true)
    expect(wire.ffcMemo).toBe('FFC for Jane Doe')
  })

  it('preserves an unrecognized status rather than failing the response', () => {
    const wire = decodeSummary({ status: 'archived' })
    expect(wire.status).toEqual({ kind: 'unrecognized', rawValue: 'archived' })
  })

  it('decodes the unpaginated collection array', () => {
    const wires = toWireSummaries([COMPLETE_WIRE, { ...COMPLETE_WIRE, id: 'other-id' }])
    expect(wires).toHaveLength(2)
    expect(wires[1]?.id).toBe('other-id')
  })

  it('rejects a collection body that is not an array', () => {
    expect(() => toWireSummaries(COMPLETE_WIRE)).toThrow()
  })

  /**
   * `billingDetails` and `bankAddress` must never enter logs, traces, crash
   * reports, or analytics. `JSON.stringify` and `console.log`/`util.inspect`
   * are the mechanisms this SDK cannot control once a caller hands a model to
   * either, so both are asserted directly, per `models/BusinessPii.ts`'s own
   * test convention.
   */
  it('redacts billingDetails and bankAddress from JSON, string, and default inspection', () => {
    const wire = decodeSummary({ bankAddress: { country: 'US' } })

    expect(JSON.stringify(wire)).not.toContain('Satoshi')
    expect(JSON.stringify(wire)).not.toContain('Money Street')
    expect(wire.toString()).not.toContain('Satoshi')
    expect(inspect(wire)).not.toContain('Satoshi')
    expect(inspect(wire.billingDetails)).not.toContain('Satoshi')
    expect(Object.keys(wire)).not.toContain('billingDetails')
    expect(JSON.stringify(wire.billingDetails)).toBe('"BillingDetails(<redacted>)"')
  })

  /**
   * `ffcMemo` is not one of the named restricted fields, but a
   * for-further-credit memo carries the end beneficiary's name, so it is held
   * to the same standard as `billingDetails.name`: absent from JSON,
   * `toString`, default inspection, and enumeration, and reachable only through
   * its accessor.
   */
  it('redacts a name-bearing ffcMemo from JSON, string, inspection, and enumeration', () => {
    const wire = decodeSummary({ ffcMemo: 'FFC for Jane Doe' })

    expect(JSON.stringify(wire)).not.toContain('Jane Doe')
    expect((JSON.parse(JSON.stringify(wire)) as { ffcMemo: string }).ffcMemo).toBe('<redacted>')
    expect(wire.toString()).not.toContain('Jane Doe')
    expect(inspect(wire)).not.toContain('Jane Doe')
    expect(Object.keys(wire)).not.toContain('ffcMemo')
    expect(JSON.stringify({ ...wire })).not.toContain('Jane Doe')
    expect(wire.ffcMemo).toBe('FFC for Jane Doe')
  })

  it('renders a null ffcMemo distinctly from a redacted one', () => {
    expect((JSON.parse(JSON.stringify(decodeSummary())) as { ffcMemo: null }).ffcMemo).toBeNull()
  })

  it('renders a null bankAddress distinctly from a redacted one', () => {
    const withAddress = decodeSummary({ bankAddress: { country: 'US' } })
    const withoutAddress = decodeSummary()

    expect((JSON.parse(JSON.stringify(withAddress)) as { bankAddress: string }).bankAddress).toBe(
      '<redacted>',
    )
    expect(
      (JSON.parse(JSON.stringify(withoutAddress)) as { bankAddress: string | null }).bankAddress,
    ).toBeNull()
  })
})

describe('wire payload', () => {
  it('decodes every WireSummary field plus transferTypesInfo', () => {
    const wire = decodeWire({
      transferTypesInfo: { wire: { currencies: ['USD', 'EUR'] } },
    })

    expect(wire.id).toBe(COMPLETE_WIRE.id)
    expect(wire.transferTypesInfo).toEqual({ wire: { currencies: ['USD', 'EUR'] } })
  })

  it('defaults transferTypesInfo to null when absent', () => {
    expect(decodeWire().transferTypesInfo).toBeNull()
  })

  it('rejects a transferTypesInfo entry with a non-string currency', () => {
    expect(() => decodeWire({ transferTypesInfo: { wire: { currencies: [1] } } })).toThrow()
  })

  it('keeps hostile transfer type names as data rather than object properties', () => {
    const transferTypesInfo = JSON.parse(
      '{"__proto__":{"currencies":["USD"]},"constructor":{"currencies":["EUR"]}}',
    ) as Record<string, unknown>
    const wire = decodeWire({ transferTypesInfo })
    const decoded = wire.transferTypesInfo

    if (decoded === null) {
      throw new Error('expected transferTypesInfo')
    }
    expect(Object.getPrototypeOf(decoded)).toBeNull()
    expect(Object.keys(decoded)).toEqual(['__proto__', 'constructor'])
    expect(decoded['__proto__']).toEqual({ currencies: ['USD'] })
    expect(decoded.constructor).toEqual({ currencies: ['EUR'] })
  })

  it('redacts billingDetails and bankAddress the same way WireSummary does', () => {
    const wire = decodeWire({ bankAddress: { country: 'US' } })
    expect(JSON.stringify(wire)).not.toContain('Satoshi')
    expect(inspect(wire)).not.toContain('Satoshi')
  })

  it('redacts a name-bearing ffcMemo the same way WireSummary does', () => {
    const wire = decodeWire({ ffcMemo: 'FFC for Jane Doe' })

    expect(JSON.stringify(wire)).not.toContain('Jane Doe')
    expect((JSON.parse(JSON.stringify(wire)) as { ffcMemo: string }).ffcMemo).toBe('<redacted>')
    expect(wire.toString()).not.toContain('Jane Doe')
    expect(inspect(wire)).not.toContain('Jane Doe')
    expect(Object.keys(wire)).not.toContain('ffcMemo')
    expect(wire.ffcMemo).toBe('FFC for Jane Doe')
  })
})

describe('wire instruction payload', () => {
  const INSTRUCTION = {
    trackingRef: 'CIR1A2B3C4',
    beneficiary: {
      name: 'CIRCLE INTERNET FINANCIAL INC',
      address1: '99 HIGH STREET',
      address2: 'BOSTON MA 02110',
    },
    beneficiaryBank: {
      name: 'WELLS FARGO BANK',
      swiftCode: 'WFBIUS6SXXX',
      routingNumber: '121000248',
      accountNumber: '****7427',
      currency: 'USD',
      address: '4250 EXECUTIVE SQUARE SUITE 300',
      city: 'LA JOLLA',
      postalCode: '02110',
      country: 'US',
    },
    virtualAccountEnabled: false,
  }

  it('decodes every field, including the Circle beneficiary identity unredacted', () => {
    const instruction = toWireInstruction(INSTRUCTION)

    expect(instruction.trackingRef).toBe('CIR1A2B3C4')
    expect(instruction.beneficiary).toEqual(INSTRUCTION.beneficiary)
    expect(instruction.virtualAccountEnabled).toBe(false)
    expect(instruction.beneficiaryBank?.routingNumber).toBe('121000248')
    expect(instruction.beneficiaryBank?.accountNumber).toBe('****7427')
  })

  it('defaults every field to null when the instruction is empty', () => {
    const instruction = toWireInstruction({})
    expect(instruction.trackingRef).toBeNull()
    expect(instruction.beneficiary).toBeNull()
    expect(instruction.beneficiaryBank).toBeNull()
    expect(instruction.virtualAccountEnabled).toBeNull()
  })

  /**
   * `routingNumber` is restricted PII. It — and the rest of `beneficiaryBank`
   * — must not enter `JSON.stringify`, `toString`, or default inspection; the
   * Circle beneficiary identity is not restricted PII and is asserted present,
   * unredacted, in the same assertion.
   */
  it('redacts beneficiaryBank (routingNumber, accountNumber) but not the Circle beneficiary', () => {
    const instruction = toWireInstruction(INSTRUCTION)

    const json = JSON.stringify(instruction)
    expect(json).not.toContain('121000248')
    expect(json).not.toContain('7427')
    expect(json).toContain('CIRCLE INTERNET FINANCIAL INC')
    expect(instruction.toString()).not.toContain('121000248')
    expect(inspect(instruction)).not.toContain('121000248')
    expect(inspect(instruction.beneficiaryBank)).not.toContain('121000248')
  })
})

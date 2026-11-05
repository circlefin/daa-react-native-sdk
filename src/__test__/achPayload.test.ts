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

import { toAch, toAchInstruction, toAchList } from '../wire/achPayload'

const COMPLETE_ACH = {
  id: 'a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd',
  type: 'ach',
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
  routingNumber: '121000248',
  createDate: '2026-01-01T00:00:00Z',
  updateDate: '2026-01-02T00:00:00Z',
}

function decode(extra: Record<string, unknown> = {}) {
  return toAch({ ...COMPLETE_ACH, ...extra })
}

describe('ach payload', () => {
  it('decodes the guaranteed core and defaults every absent enrichment', () => {
    const ach = decode()

    expect(ach.id).toBe(COMPLETE_ACH.id)
    expect(ach.status).toEqual({ kind: 'complete' })
    expect(ach.description).toBe(COMPLETE_ACH.description)
    expect(ach.trackingRef).toBe(COMPLETE_ACH.trackingRef)
    expect(ach.fingerprint).toBe(COMPLETE_ACH.fingerprint)
    expect(ach.billingDetails.name).toBe('Satoshi Nakamoto')
    expect(ach.routingNumber).toBe('121000248')
    expect(ach.bankAddress).toBeNull()
  })

  it('rejects an ACH account missing a guaranteed field', () => {
    const partial: Record<string, unknown> = { ...COMPLETE_ACH }
    delete partial.billingDetails
    expect(() => toAch(partial)).toThrow()
  })

  it('defaults routingNumber to null when the service omits it', () => {
    const partial: Record<string, unknown> = { ...COMPLETE_ACH }
    delete partial.routingNumber
    expect(toAch(partial).routingNumber).toBeNull()
  })

  it('decodes the unpaginated collection array (the full ACH projection, not a summary)', () => {
    const list = toAchList([COMPLETE_ACH, { ...COMPLETE_ACH, id: 'other-id' }])
    expect(list).toHaveLength(2)
    expect(list[0]?.routingNumber).toBe('121000248')
    expect(list[1]?.id).toBe('other-id')
  })

  it('rejects a collection body that is not an array', () => {
    expect(() => toAchList(COMPLETE_ACH)).toThrow()
  })

  /**
   * ACH `routingNumber` is restricted PII, alongside `billingDetails` and
   * `bankAddress`. All three must never enter logs,
   * traces, crash reports, or analytics.
   */
  it('redacts billingDetails, bankAddress, and routingNumber from JSON and default inspection', () => {
    const ach = decode({ bankAddress: { country: 'US' } })

    const json = JSON.stringify(ach)
    expect(json).not.toContain('Satoshi')
    expect(json).not.toContain('121000248')
    expect(ach.toString()).not.toContain('121000248')
    expect(inspect(ach)).not.toContain('121000248')
    expect(Object.keys(ach)).not.toContain('routingNumber')
    expect(Object.keys(ach)).not.toContain('billingDetails')
  })

  it('renders a present routingNumber as redacted rather than null', () => {
    const rendered = JSON.parse(JSON.stringify(decode())) as { routingNumber: string }
    expect(rendered.routingNumber).toBe('<redacted>')
  })
})

describe('ach instruction payload', () => {
  const INSTRUCTION = {
    trackingRef: 'CIR1A2B3C4',
    beneficiary: {
      name: 'CIRCLE INTERNET FINANCIAL INC',
      address1: '99 HIGH STREET',
      address2: 'BOSTON MA 02110',
    },
    beneficiaryBank: {
      name: 'WELLS FARGO BANK',
      routingNumber: '121000248',
      accountNumber: '****7427',
      address: '4250 EXECUTIVE SQUARE SUITE 300',
      city: 'LA JOLLA',
      postalCode: '02110',
      country: 'US',
    },
  }

  it('decodes every field, including the Circle beneficiary identity unredacted', () => {
    const instruction = toAchInstruction(INSTRUCTION)

    expect(instruction.trackingRef).toBe('CIR1A2B3C4')
    expect(instruction.beneficiary).toEqual(INSTRUCTION.beneficiary)
    expect(instruction.beneficiaryBank?.routingNumber).toBe('121000248')
  })

  it('defaults every field to null when the instruction is empty', () => {
    const instruction = toAchInstruction({})
    expect(instruction.trackingRef).toBeNull()
    expect(instruction.beneficiary).toBeNull()
    expect(instruction.beneficiaryBank).toBeNull()
  })

  it('redacts beneficiaryBank (routingNumber, accountNumber) but not the Circle beneficiary', () => {
    const instruction = toAchInstruction(INSTRUCTION)

    const json = JSON.stringify(instruction)
    expect(json).not.toContain('121000248')
    expect(json).not.toContain('7427')
    expect(json).toContain('CIRCLE INTERNET FINANCIAL INC')
    expect(instruction.toString()).not.toContain('121000248')
    expect(inspect(instruction)).not.toContain('121000248')
  })
})

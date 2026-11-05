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

import type {
  DepositAccountLocation,
  DepositRiskEvaluation,
  DepositSourceLocation,
  DepositStatus,
  DepositType,
} from '../models/Deposit'
import { Deposit } from '../models/Deposit'
import { DepositSummary } from '../models/DepositSummary'
import { optionalMoney, requiredMoney } from './moneyPayload'
import {
  asObject,
  MalformedPayloadError,
  optionalObject,
  optionalString,
  requiredString,
  unrecognized,
} from './payload'

// Wire-string to public-type mapping. A `Map`, not an object literal — the same
// `Object.prototype` hazard `wireEnums.ts` guards against, where
// `lookup['constructor']` would "recognise" a hostile value as something that is
// not a status at all.

const DEPOSIT_STATUSES = new Map<string, DepositStatus>([
  ['pending', Object.freeze({ kind: 'pending' as const })],
  ['complete', Object.freeze({ kind: 'complete' as const })],
  ['failed', Object.freeze({ kind: 'failed' as const })],
])

const DEPOSIT_TYPES = new Map<string, DepositType>([
  ['wire', Object.freeze({ kind: 'wire' as const })],
  ['ach', Object.freeze({ kind: 'ach' as const })],
  ['cbit', Object.freeze({ kind: 'cbit' as const })],
  ['rtgs', Object.freeze({ kind: 'rtgs' as const })],
  ['rtp', Object.freeze({ kind: 'rtp' as const })],
  ['xpay', Object.freeze({ kind: 'xpay' as const })],
  ['signet', Object.freeze({ kind: 'signet' as const })],
  ['sepa', Object.freeze({ kind: 'sepa' as const })],
  ['sepa_instant', Object.freeze({ kind: 'sepa_instant' as const })],
  ['sen', Object.freeze({ kind: 'sen' as const })],
  ['pix', Object.freeze({ kind: 'pix' as const })],
  ['cubix', Object.freeze({ kind: 'cubix' as const })],
  ['book_transfer', Object.freeze({ kind: 'book_transfer' as const })],
  ['fed_now', Object.freeze({ kind: 'fed_now' as const })],
])

function toDepositStatus(raw: string): DepositStatus {
  return DEPOSIT_STATUSES.get(raw) ?? unrecognized(raw)
}

function toDepositType(raw: string): DepositType {
  return DEPOSIT_TYPES.get(raw) ?? unrecognized(raw)
}

/**
 * The destination location has one `type` constant (`account`), but `type` is
 * an ordinary string discriminator rather than something this SDK can prove
 * closed — see the type's doc comment in `models/Deposit.ts`.
 */
function toDepositAccountLocation(payload: Record<string, unknown>): DepositAccountLocation {
  const type = requiredString(payload, 'type', 'destination.type')
  if (type !== 'account') {
    return unrecognized(type)
  }
  return Object.freeze({
    kind: 'account' as const,
    accountId: requiredString(payload, 'id', 'destination.id'),
  })
}

/**
 * `type` and `id` are guaranteed together here: the service returns a source
 * location only when both parse, so a decoded source location
 * never has one without the other.
 */
function toDepositSourceLocation(payload: Record<string, unknown>): DepositSourceLocation {
  return Object.freeze({
    type: toDepositType(requiredString(payload, 'type', 'source.type')),
    id: requiredString(payload, 'id', 'source.id'),
    name: optionalString(payload, 'name'),
  })
}

function toDepositRiskEvaluation(payload: Record<string, unknown>): DepositRiskEvaluation {
  return Object.freeze({
    decision: optionalString(payload, 'decision', 'riskEvaluation.decision'),
    reason: optionalString(payload, 'reason'),
  })
}

/**
 * Map a decoded deposit payload onto the public model.
 *
 * Unknown *additional* fields are ignored and an unfamiliar *present* closed-set
 * value degrades to `unrecognized`; a missing guaranteed field throws. See the
 * class note on `Deposit` for exactly which fields are guaranteed and why that
 * set does not follow the OpenAPI schema's required marking.
 *
 * @throws MalformedPayloadError
 */
export function toDeposit(value: unknown): Deposit {
  const payload = asObject(value, 'deposit')

  const destinationPayload = optionalObject(payload, 'destination')
  const sourcePayload = optionalObject(payload, 'source')
  const riskEvaluationPayload = optionalObject(payload, 'riskEvaluation')

  return new Deposit({
    amount: requiredMoney(payload, 'amount'),
    createDate: requiredString(payload, 'createDate'),
    customerExternalRef: optionalString(payload, 'customerExternalRef'),
    destination: destinationPayload === null ? null : toDepositAccountLocation(destinationPayload),
    errorCode: optionalString(payload, 'errorCode'),
    externalRef: optionalString(payload, 'externalRef'),
    fee: optionalMoney(payload, 'fee'),
    fees: optionalMoney(payload, 'fees'),
    fromAmount: optionalMoney(payload, 'fromAmount'),
    id: requiredString(payload, 'id'),
    riskEvaluation:
      riskEvaluationPayload === null ? null : toDepositRiskEvaluation(riskEvaluationPayload),
    source: sourcePayload === null ? null : toDepositSourceLocation(sourcePayload),
    sourceAccountId: optionalString(payload, 'sourceAccountId'),
    status: toDepositStatus(requiredString(payload, 'status')),
    trackingRef: optionalString(payload, 'trackingRef'),
    updateDate: optionalString(payload, 'updateDate'),
  })
}

/**
 * Map a decoded deposit-collection element onto the public `DepositSummary`.
 *
 * Same required/optional line as {@link toDeposit} — see `models/DepositSummary.ts`'s
 * class note for why the service's `DepositSummary` response has no `source`,
 * `fees`, `fromAmount`, or `trackingRef` at all, rather than merely omitting
 * them from this projection.
 *
 * @throws MalformedPayloadError
 */
export function toDepositSummary(value: unknown): DepositSummary {
  const payload = asObject(value, 'deposit')

  const destinationPayload = optionalObject(payload, 'destination')
  const riskEvaluationPayload = optionalObject(payload, 'riskEvaluation')

  return new DepositSummary({
    amount: requiredMoney(payload, 'amount'),
    createDate: requiredString(payload, 'createDate'),
    customerExternalRef: optionalString(payload, 'customerExternalRef'),
    destination: destinationPayload === null ? null : toDepositAccountLocation(destinationPayload),
    errorCode: optionalString(payload, 'errorCode'),
    externalRef: optionalString(payload, 'externalRef'),
    fee: optionalMoney(payload, 'fee'),
    id: requiredString(payload, 'id'),
    riskEvaluation:
      riskEvaluationPayload === null ? null : toDepositRiskEvaluation(riskEvaluationPayload),
    sourceAccountId: optionalString(payload, 'sourceAccountId'),
    status: toDepositStatus(requiredString(payload, 'status')),
    updateDate: optionalString(payload, 'updateDate'),
  })
}

export function toDepositSummaries(value: unknown): readonly DepositSummary[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('deposits')
  }
  return Object.freeze(value.map(toDepositSummary))
}

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
  WithdrawalAdjustments,
  WithdrawalDestination,
  WithdrawalDestinationType,
  WithdrawalErrorCode,
  WithdrawalPolicyEvaluation,
  WithdrawalReturn,
  WithdrawalRiskEvaluation,
  WithdrawalStatus,
  WithdrawalSubAccountSweep,
  WithdrawalSweepStatus,
} from '../models/Withdrawal'
import { WithdrawalDetail, WithdrawalToAmount } from '../models/Withdrawal'
import { JSON_NUMBER } from './jsonNumber'
import { optionalMoney, requiredMoney } from './moneyPayload'
import {
  MalformedPayloadError,
  asObject,
  optionalObject,
  optionalString,
  requiredString,
  unrecognized,
} from './payload'

const STATUSES = new Map<string, WithdrawalStatus>([
  ['pending', Object.freeze({ kind: 'pending' as const })],
  ['complete', Object.freeze({ kind: 'complete' as const })],
  ['failed', Object.freeze({ kind: 'failed' as const })],
])

const ERROR_CODES = new Map<string, WithdrawalErrorCode>(
  [
    'insufficient_funds',
    'transaction_denied',
    'transaction_failed',
    'transaction_returned',
    'bank_transaction_error',
    'fiat_account_limit_exceeded',
    'invalid_bank_account_number',
    'invalid_ach_rtn',
    'invalid_wire_rtn',
    'vendor_inactive',
    'payout_canceled',
    'invalid_travel_rule_identity',
    'intermediary_bank_required',
    'sen_not_supported',
  ].map((kind) => [kind, Object.freeze({ kind }) as WithdrawalErrorCode]),
)

const DESTINATION_TYPES = new Map<string, WithdrawalDestinationType>([
  ['wire', Object.freeze({ kind: 'wire' as const })],
  ['ach', Object.freeze({ kind: 'ach' as const })],
])

const SWEEP_STATUSES = new Map<string, WithdrawalSweepStatus>([
  ['pending', Object.freeze({ kind: 'pending' as const })],
  ['complete', Object.freeze({ kind: 'complete' as const })],
  ['failed', Object.freeze({ kind: 'failed' as const })],
  ['skipped', Object.freeze({ kind: 'skipped' as const })],
])

function optionalBoolean(payload: Record<string, unknown>, name: string): boolean | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  if (typeof value !== 'boolean') {
    throw new MalformedPayloadError(name)
  }
  return value
}

function toDestination(payload: Record<string, unknown>): WithdrawalDestination {
  const rawType = requiredString(payload, 'type', 'destination.type')
  return Object.freeze({
    type: DESTINATION_TYPES.get(rawType) ?? unrecognized(rawType),
    id: requiredString(payload, 'id', 'destination.id'),
    name: optionalString(payload, 'name', 'destination.name'),
  })
}

function toRiskEvaluation(payload: Record<string, unknown>): WithdrawalRiskEvaluation {
  return Object.freeze({
    decision: optionalString(payload, 'decision', 'riskEvaluation.decision'),
    reason: optionalString(payload, 'reason', 'riskEvaluation.reason'),
  })
}

function toPolicyEvaluation(payload: Record<string, unknown>): WithdrawalPolicyEvaluation {
  return Object.freeze({ status: requiredString(payload, 'status', 'policyEvaluation.status') })
}

function toToAmount(payload: Record<string, unknown>): WithdrawalToAmount {
  const amount = optionalString(payload, 'amount', 'toAmount.amount')
  if (amount !== null && !JSON_NUMBER.test(amount)) {
    throw new MalformedPayloadError('toAmount.amount')
  }
  return new WithdrawalToAmount(amount, optionalString(payload, 'currency', 'toAmount.currency'))
}

function toAdjustments(payload: Record<string, unknown>): WithdrawalAdjustments {
  return Object.freeze({
    fxCredit: optionalMoney(payload, 'fxCredit'),
    fxDebit: optionalMoney(payload, 'fxDebit'),
  })
}

function optionalStatus(payload: Record<string, unknown>, name: string): WithdrawalStatus | null {
  const raw = optionalString(payload, name, `return.${name}`)
  return raw === null ? null : (STATUSES.get(raw) ?? unrecognized(raw))
}

function toReturn(payload: Record<string, unknown>): WithdrawalReturn {
  return Object.freeze({
    id: optionalString(payload, 'id', 'return.id'),
    payoutId: optionalString(payload, 'payoutId', 'return.payoutId'),
    amount: optionalMoney(payload, 'amount'),
    fees: optionalMoney(payload, 'fees'),
    reason: optionalString(payload, 'reason', 'return.reason'),
    status: optionalStatus(payload, 'status'),
    createDate: optionalString(payload, 'createDate', 'return.createDate'),
    updateDate: optionalString(payload, 'updateDate', 'return.updateDate'),
  })
}

function toSweep(value: unknown, index: number): WithdrawalSubAccountSweep {
  const payload = asObject(value, `subAccountSweeps[${index}]`)
  const rawStatus = optionalString(payload, 'status', `subAccountSweeps[${index}].status`)
  return Object.freeze({
    subAccountId: optionalString(
      payload,
      'subAccountId',
      `subAccountSweeps[${index}].subAccountId`,
    ),
    amount: optionalMoney(payload, 'amount'),
    status: rawStatus === null ? null : (SWEEP_STATUSES.get(rawStatus) ?? unrecognized(rawStatus)),
  })
}

function toSweeps(payload: Record<string, unknown>): readonly WithdrawalSubAccountSweep[] {
  const value = payload.subAccountSweeps
  if (value === undefined || value === null) {
    return Object.freeze([])
  }
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('subAccountSweeps')
  }
  return Object.freeze(value.map(toSweep))
}

/** Decode the GET-only withdrawal detail payload from the standard data envelope. */
export function toWithdrawalDetail(value: unknown): WithdrawalDetail {
  const payload = asObject(value, 'withdrawal')
  const destination = optionalObject(payload, 'destination')
  if (destination === null) {
    throw new MalformedPayloadError('destination')
  }
  const rawStatus = requiredString(payload, 'status')
  const rawErrorCode = optionalString(payload, 'errorCode')
  const toAmount = optionalObject(payload, 'toAmount')
  const riskEvaluation = optionalObject(payload, 'riskEvaluation')
  const adjustments = optionalObject(payload, 'adjustments')
  const returnObject = optionalObject(payload, 'return')
  const policyEvaluation = optionalObject(payload, 'policyEvaluation')

  return new WithdrawalDetail({
    id: requiredString(payload, 'id'),
    sourceAccountId: requiredString(payload, 'sourceAccountId'),
    destination: toDestination(destination),
    amount: requiredMoney(payload, 'amount'),
    toAmount: toAmount === null ? null : toToAmount(toAmount),
    fees: optionalMoney(payload, 'fees'),
    status: STATUSES.get(rawStatus) ?? unrecognized(rawStatus),
    trackingRef: optionalString(payload, 'trackingRef'),
    errorCode:
      rawErrorCode === null ? null : (ERROR_CODES.get(rawErrorCode) ?? unrecognized(rawErrorCode)),
    externalRef: optionalString(payload, 'externalRef'),
    riskEvaluation: riskEvaluation === null ? null : toRiskEvaluation(riskEvaluation),
    adjustments: adjustments === null ? null : toAdjustments(adjustments),
    returnObject: returnObject === null ? null : toReturn(returnObject),
    customerExternalRef: optionalString(payload, 'customerExternalRef'),
    burnAll: optionalBoolean(payload, 'burnAll'),
    subAccountSweeps: toSweeps(payload),
    createDate: requiredString(payload, 'createDate'),
    updateDate: optionalString(payload, 'updateDate'),
    policyEvaluation: policyEvaluation === null ? null : toPolicyEvaluation(policyEvaluation),
  })
}

/**
 * Decode a withdrawal list page's `data` array.
 *
 * Each row is decoded by {@link toWithdrawalDetail}, so `policyEvaluation` is
 * decoded when a row carries it and is `null` when the row omits it.
 */
export function toWithdrawalDetails(value: unknown): readonly WithdrawalDetail[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('withdrawals')
  }
  return Object.freeze(value.map(toWithdrawalDetail))
}

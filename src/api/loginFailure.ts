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

import {
  contractViolation,
  idempotencyConflict,
  loginRequestExpired,
  type DaaError,
} from '../errors'
import type { DaaHttpResponse } from '../transport/DaaTransport'
import { headerValueIgnoringCase } from '../transport/headers'
import { isDaaStatus } from '../wire/daaStatusCodes'
import { readDaaStatusCode } from '../wire/errorEnvelope'

/**
 * The failure the three login calls (Prepare, Social Session, and Device
 * Registration Complete) classify themselves, or `null` when the response is
 * left to `decodeResourceResponse`, which decodes the success status and turns
 * every other status into `api`.
 *
 * Classified on the numeric code only (a non-numeric string `code`, even a
 * name such as `IDEMPOTENCY_KEY_REUSED`, is left to `api`):
 *
 * - `410` is `login_request_expired`.
 * - `IDEMPOTENCY_KEY_REUSED` (`420034`) on a `409` is `idempotency_conflict`,
 *   with the key the SDK minted for this request. That key is in the bytes the
 *   SDK serialized and sent, so it is never read from the response.
 * - `LOGIN_REQUEST_CONSUMED` (`420039`) is `contract_violation`. An identical
 *   successful step converges and never returns it, so it means that a
 *   different request used the login request.
 * - DAA also returns `409` for `AUTH_KEY_BINDING_CONFLICT` (`420038`), which
 *   classifies as `api`, not retryable. A `409` without a code that this
 *   SDK classifies, or without a readable body, is `api` too. So no status
 *   alone produces `idempotency_conflict`.
 *
 * A `2xx` response is never classified here, even when its body has a `code`.
 */
export function loginStepFailure(
  response: DaaHttpResponse,
  idempotencyKey: string,
): DaaError | null {
  const correlationId = headerValueIgnoringCase(response.headers, 'X-Request-Id')
  if (response.status === 410) {
    return loginRequestExpired(correlationId)
  }
  if (response.status >= 200 && response.status < 300) {
    return null
  }
  const daaStatusCode = readDaaStatusCode(response.bodyBytes)
  if (response.status === 409 && isDaaStatus(daaStatusCode, 'IDEMPOTENCY_KEY_REUSED')) {
    return idempotencyConflict(idempotencyKey, correlationId)
  }
  if (isDaaStatus(daaStatusCode, 'LOGIN_REQUEST_CONSUMED')) {
    return contractViolation(
      'the login request was already used by a different request',
      correlationId,
    )
  }
  return null
}

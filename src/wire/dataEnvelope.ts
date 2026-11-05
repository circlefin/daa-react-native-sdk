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

import { malformedResponse } from '../errors'

/**
 * The DAA service wraps every **public** success response in `data`, and there is
 * exactly one envelope.
 *
 * Every public resource wraps its payload under that key: accounts,
 * transfers, withdrawals, deposits, deposit addresses, transactions, and the
 * bank instruction reads.
 *
 * The OpenAPI schema does not show the wrapper, so a client generated
 * from the schema decodes the wrong root and reads every field as absent.
 */
const ENVELOPE_KEY = 'data'

/**
 * Decode a DAA public success body: validate UTF-8, unwrap the `data` envelope,
 * and hand back the value under it.
 *
 * Everything that can go wrong — a body that is not UTF-8, a body that is not
 * JSON, a body whose payload sits at the root, an envelope present but empty —
 * becomes the one `contract_violation` carrying the correlation id, and nothing
 * else. An envelope present but empty is malformed rather than an absent value:
 * the wrapper is not optional on a successful response.
 *
 * The decoder's own message is never attached. `JSON.parse` quotes the offending
 * input, and the SDK cannot know what a misrouted or intercepted response
 * contains.
 *
 * UTF-8 validation is strict (`fatal: true`) rather than replacing a bad sequence
 * with U+FFFD: a replacement character is a legal JSON string character, so
 * lenient decoding would accept bytes the contract does not describe and hand the
 * caller a field the service never sent. That only bites for bytes inside a field
 * the payload does not read — an invalid byte in a declared field usually breaks
 * the JSON as well — which is exactly why the guard has to be here rather than
 * left to the parser.
 */
export function decodeDataEnvelope(bytes: Uint8Array, correlationId: string | null): unknown {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw malformedResponse(correlationId)
  }

  let root: unknown
  try {
    root = JSON.parse(text)
  } catch {
    throw malformedResponse(correlationId)
  }

  if (typeof root !== 'object' || root === null || Array.isArray(root)) {
    throw malformedResponse(correlationId)
  }

  const data = (root as Record<string, unknown>)[ENVELOPE_KEY]
  if (data === undefined || data === null) {
    throw malformedResponse(correlationId)
  }
  return data
}

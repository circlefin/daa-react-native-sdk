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

import { apiFailure, malformedResponse, type DaaError } from '../errors'
import { headerValueIgnoringCase } from '../transport/headers'
import type { DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { decodeDataEnvelope } from '../wire/dataEnvelope'
import { readDaaStatusCode } from '../wire/errorEnvelope'
import { MalformedPayloadError } from '../wire/payload'

type ReadResourceOptions<T> = Readonly<{
  transport: DaaTransport
  path: string
  /**
   * Exact percent-encoded query without the leading `?`, or `null`/omitted for
   * none. Unlike a signed write (signed v1 endpoints do not accept query
   * parameters), an unsigned read may carry one — see the
   * `DaaTransport.query` note — so this is opt-in per call.
   */
  query?: string | null
  decode: (value: unknown) => T
}>

type PostResourceOptions<T> = Readonly<{
  transport: DaaTransport
  path: string
  query: string | null
  headers: Readonly<Record<string, string>>
  /** Final serialized bytes. Signed writes must sign and pass this same slice. */
  bodyBytes: Uint8Array
  expectedStatus: number
  decode: (value: unknown) => T
  /**
   * Endpoint-specific classification of a response, checked before the
   * expected status.
   * A non-`null` result is thrown; `null` leaves the response to the common
   * contract.
   */
  failure?: (response: DaaHttpResponse) => DaaError | null
}>

type DecodeResourceResponseOptions<T> = Readonly<{
  response: DaaHttpResponse
  expectedStatus: number
  decode: (value: unknown) => T
}>

/** Decode the common exact-status public resource response contract. */
export function decodeResourceResponse<T>({
  response,
  expectedStatus,
  decode,
}: DecodeResourceResponseOptions<T>): T {
  const correlationId = headerValueIgnoringCase(response.headers, 'X-Request-Id')

  if (response.status !== expectedStatus) {
    throw apiFailure({
      httpStatus: response.status,
      daaStatusCode: readDaaStatusCode(response.bodyBytes),
      correlationId,
    })
  }
  if (response.bodyBytes === null) {
    throw malformedResponse(correlationId)
  }

  const data = decodeDataEnvelope(response.bodyBytes, correlationId)
  try {
    return decode(data)
  } catch (err) {
    if (err instanceof MalformedPayloadError) {
      throw malformedResponse(correlationId)
    }
    throw err
  }
}

/** Execute the common public GET contract, with an optional exact query string. */
export async function readResource<T>({
  transport,
  path,
  query,
  decode,
}: ReadResourceOptions<T>): Promise<T> {
  const response = await transport.send({
    method: 'GET',
    path,
    query: query ?? null,
    headers: {},
    bodyBytes: null,
  })
  // These by-id reads document exactly 200. Other statuses, including another
  // 2xx, are observable API failures rather than silently accepted variants.
  return decodeResourceResponse({ response, expectedStatus: 200, decode })
}

/** Execute a public POST without transforming its endpoint-specific request. */
export async function postResource<T>({
  transport,
  path,
  query,
  headers,
  bodyBytes,
  expectedStatus,
  decode,
  failure,
}: PostResourceOptions<T>): Promise<T> {
  const response = await transport.send({
    method: 'POST',
    path,
    query,
    headers,
    bodyBytes,
  })
  const mapped = failure?.(response) ?? null
  if (mapped !== null) {
    throw mapped
  }
  return decodeResourceResponse({ response, expectedStatus, decode })
}

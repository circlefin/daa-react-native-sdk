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

import { isDaaError, malformedResponse } from '../errors'
import { Page } from '../models/Page'
import type { DaaTransport } from '../transport/DaaTransport'
import { headerValueIgnoringCase } from '../transport/headers'
import { trustedPaginationTargets } from '../wire/paginationLinks'
import type { TrustedPaginationTargets } from '../wire/paginationLinks'
import { decodeResourceResponse } from './resourceRequest'

type PageRequestOptions<T> = Readonly<{
  transport: DaaTransport
  publicApiOrigin: string
  path: string
  query: string | null
  decode: (value: unknown) => readonly T[]
}>

/** Load one exact collection request and bind its links to the same collection. */
export async function readPage<T>(options: PageRequestOptions<T>): Promise<Page<T>> {
  const response = await options.transport.send({
    method: 'GET',
    path: options.path,
    query: options.query,
    headers: {},
    bodyBytes: null,
  })
  const items = decodeResourceResponse({ response, expectedStatus: 200, decode: options.decode })
  let targets: TrustedPaginationTargets
  try {
    targets = trustedPaginationTargets(response, options.publicApiOrigin, options.path)
  } catch (err) {
    if (isDaaError(err) && err.detail.kind === 'contract_violation') {
      throw malformedResponse(headerValueIgnoringCase(response.headers, 'X-Request-Id'))
    }
    throw err
  }
  const load = (query: string | null): Promise<Page<T>> => readPage({ ...options, query })
  const nextQuery = targets.next?.query
  const previousQuery = targets.previous?.query

  return new Page(
    items,
    targets.next === null ? null : () => load(nextQuery ?? null),
    targets.previous === null ? null : () => load(previousQuery ?? null),
  )
}

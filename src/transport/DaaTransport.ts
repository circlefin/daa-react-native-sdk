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

// Injected transport boundary. The SDK never embeds a DAA service credential; a
// consumer supplies transport that carries exact request bytes to the DAA public
// API (directly, or through a consumer backend relay).

export type DaaHttpRequest = Readonly<{
  method: string
  /** Signed public API path beginning `/v1` — not a consumer-backend route. */
  path: string
  /** Exact percent-encoded query without the leading `?`, or null. */
  query: string | null
  headers: Readonly<Record<string, string>>
  /** Immutable body bytes. The SDK signs and sends this same slice. */
  bodyBytes: Uint8Array | null
}>

export type DaaHttpResponse = Readonly<{
  status: number
  headers: Readonly<Record<string, string>>
  bodyBytes: Uint8Array | null
}>

export interface DaaTransport {
  send(request: DaaHttpRequest): Promise<DaaHttpResponse>
}

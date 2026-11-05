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

/**
 * Look a response header up without assuming its casing.
 *
 * HTTP field names are case-insensitive and HTTP/2 mandates lowercase on the
 * wire, so a `fetch`-based transport may surface `x-request-id` where another
 * surfaces `X-Request-Id`. `DaaHttpResponse` deliberately does not normalize —
 * the transport is the consumer's — so the typed client, which is the first thing
 * that reads a response header, owns the lookup.
 *
 * Returns `null` for an absent header. Absence is reported as absence rather than
 * as an empty string, which a provider could also legitimately send.
 */
export function headerValueIgnoringCase(
  headers: Readonly<Record<string, string>>,
  name: string,
): string | null {
  const exact = headers[name]
  if (exact !== undefined) {
    return exact
  }
  const wanted = name.toLowerCase()
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === wanted) {
      return headers[key] ?? null
    }
  }
  return null
}

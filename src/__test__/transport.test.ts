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

import { serializeBody } from '../crypto/serialization'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

class RecordingTransport implements DaaTransport {
  public last: DaaHttpRequest | undefined
  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.last = request
    return { status: 200, headers: {}, bodyBytes: null }
  }
}

describe('DaaTransport boundary', () => {
  it('carries the exact serialized body bytes without mutation', async () => {
    const transport = new RecordingTransport()
    const body = serializeBody({ idempotencyKey: 'k', amount: '1.00' })

    const request: DaaHttpRequest = {
      method: 'POST',
      path: '/v1/accounts/transfers',
      query: null, // signed v1 operations require query=null
      headers: { 'Content-Type': 'application/json' },
      bodyBytes: body,
    }
    await transport.send(request)

    expect(transport.last?.bodyBytes).toBe(body) // same immutable slice
    expect(new TextDecoder().decode(transport.last!.bodyBytes!)).toBe(
      '{"idempotencyKey":"k","amount":"1.00"}',
    )
    expect(transport.last?.query).toBeNull()
  })
})

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

import { idempotencyConflict, isDaaError } from '../errors'
import { postResource, readResource } from '../api/resourceRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { MalformedPayloadError } from '../wire/payload'

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

async function detailOf(operation: Promise<unknown>) {
  try {
    await operation
  } catch (err) {
    if (isDaaError(err)) {
      return err.detail
    }
    throw err
  }
  throw new Error('expected the operation to fail')
}

describe('readResource', () => {
  it('sends the bodyless by-id GET shape and decodes the data envelope', async () => {
    const transport = new RecordingTransport({
      status: 200,
      headers: {},
      bodyBytes: bytes('{"data":{"id":"resource-1"}}'),
    })

    const result = await readResource({
      transport,
      path: '/v1/resources/resource-1',
      decode: (value) => (value as { id: string }).id,
    })

    expect(result).toBe('resource-1')
    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: '/v1/resources/resource-1',
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
  })

  it('rejects every status other than the documented 200', async () => {
    for (const status of [201, 204, 299, 400, Number.NaN]) {
      const transport = new RecordingTransport({
        status,
        headers: { 'x-request-id': 'req-1' },
        bodyBytes: bytes('{"status":{"code":"UNEXPECTED"}}'),
      })
      const detail = await detailOf(
        readResource({ transport, path: '/v1/resources/resource-1', decode: (value) => value }),
      )
      expect(detail).toMatchObject({
        kind: 'api',
        httpStatus: status,
        daaStatusCode: 'UNEXPECTED',
      })
    }
  })

  it('carries the root numeric code of the flat body DAA sends', async () => {
    const transport = new RecordingTransport({
      status: 400,
      headers: { 'x-request-id': 'req-1' },
      bodyBytes: bytes('{"code":420001,"message":"internal detail","externalMessage":"rejected"}'),
    })
    const detail = await detailOf(
      readResource({ transport, path: '/v1/resources/resource-1', decode: (value) => value }),
    )
    expect(detail).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: 420001,
      retryable: false,
    })
  })

  it('maps malformed decoded payloads to contract violations with the correlation id', async () => {
    const transport = new RecordingTransport({
      status: 200,
      headers: { 'X-Request-Id': 'req-2' },
      bodyBytes: bytes('{"data":{}}'),
    })
    await expect(
      detailOf(
        readResource({
          transport,
          path: '/v1/resources/resource-1',
          decode: () => {
            throw new MalformedPayloadError('id')
          },
        }),
      ),
    ).resolves.toEqual({ kind: 'contract_violation', correlationId: 'req-2' })
  })

  it('preserves transport failures unchanged', async () => {
    const failure = new Error('dns')
    const transport: DaaTransport = {
      async send() {
        throw failure
      },
    }
    await expect(
      readResource({ transport, path: '/v1/resources/resource-1', decode: (value) => value }),
    ).rejects.toBe(failure)
  })
})

describe('postResource', () => {
  it('sends the final request bytes unchanged and decodes the expected response', async () => {
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: bytes('{"data":{"id":"resource-1"}}'),
    })
    const bodyBytes = bytes('{"idempotencyKey":"request-1"}')
    const headers = Object.freeze({
      'Content-Type': 'application/json',
      'X-Device-Signature': 'signature-1',
    })

    const result = await postResource({
      transport,
      path: '/v1/resources',
      query: 'custodyType=self',
      headers,
      bodyBytes,
      expectedStatus: 201,
      decode: (value) => (value as { id: string }).id,
    })

    expect(result).toBe('resource-1')
    expect(transport.sent).toEqual([
      {
        method: 'POST',
        path: '/v1/resources',
        query: 'custodyType=self',
        headers,
        bodyBytes,
      },
    ])
    expect(transport.sent[0]?.bodyBytes).toBe(bodyBytes)
  })

  it('throws an endpoint-specific failure before the expected-status check', async () => {
    const response = { status: 409, headers: {}, bodyBytes: bytes('{"code":420034}') }
    const transport = new RecordingTransport(response)
    const conflict = idempotencyConflict('request-1', null)
    const seen: unknown[] = []

    await expect(
      postResource({
        transport,
        path: '/v1/resources',
        query: null,
        headers: {},
        bodyBytes: bytes('{}'),
        expectedStatus: 201,
        decode: (value) => value,
        failure: (received) => {
          seen.push(received)
          return conflict
        },
      }),
    ).rejects.toBe(conflict)
    expect(seen).toEqual([response])
  })

  it('applies the common contract when the endpoint-specific failure returns null', async () => {
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: bytes('{"data":{"id":"resource-1"}}'),
    })

    await expect(
      postResource({
        transport,
        path: '/v1/resources',
        query: null,
        headers: {},
        bodyBytes: bytes('{}'),
        expectedStatus: 201,
        decode: (value) => (value as { id: string }).id,
        failure: () => null,
      }),
    ).resolves.toBe('resource-1')
  })

  it('requires the endpoint-specific expected status', async () => {
    const transport = new RecordingTransport({
      status: 200,
      headers: { 'x-request-id': 'req-post' },
      bodyBytes: bytes('{"data":{"id":"resource-1"}}'),
    })

    await expect(
      detailOf(
        postResource({
          transport,
          path: '/v1/resources',
          query: null,
          headers: {},
          bodyBytes: bytes('{}'),
          expectedStatus: 201,
          decode: (value) => value,
        }),
      ),
    ).resolves.toEqual({
      kind: 'api',
      httpStatus: 200,
      retryable: false,
    })
  })
})

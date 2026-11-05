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

import { isUuid, isUuidV4 } from '../validation/uuid'

describe('isUuid', () => {
  it.each(['8f3c1e2a-4b5d-4e6f-9a0b-1c2d3e4f5a6b', '8F3C1E2A-4B5D-4E6F-9A0B-1C2D3E4F5A6B'])(
    'accepts a hyphenated UUID: %s',
    (value) => {
      expect(isUuid(value)).toBe(true)
    },
  )

  it.each([
    '',
    'not-a-uuid',
    '8f3c1e2a4b5d4e6f9a0b1c2d3e4f5a6b',
    '8f3c1e2a-4b5d-4e6f-9a0b-1c2d3e4f5a6',
    '8f3c1e2a-4b5d-4e6f-9a0b-1c2d3e4f5a6b/',
  ])('rejects a value that is not a UUID: %s', (value) => {
    expect(isUuid(value)).toBe(false)
  })
})

describe('isUuidV4', () => {
  it('accepts UUID v4 values with every RFC variant nibble', () => {
    for (const variant of ['8', '9', 'a', 'B']) {
      expect(isUuidV4(`22222222-2222-4222-${variant}222-222222222222`)).toBe(true)
    }
  })

  it('rejects other versions, invalid variants, and generic malformed UUIDs', () => {
    for (const value of [
      '22222222-2222-1222-a222-222222222222',
      '22222222-2222-5222-a222-222222222222',
      '22222222-2222-4222-7222-222222222222',
      '22222222-2222-4222-c222-222222222222',
      'not-a-uuid',
    ]) {
      expect(isUuidV4(value)).toBe(false)
    }
  })
})

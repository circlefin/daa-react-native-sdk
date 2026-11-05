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

import { assertAuthKeyMatchesContext, bindAuthKeyToContext } from '../models/DaaUserContext'
import { toDeviceRegistrationResult } from '../wire/deviceRegistrationResultPayload'
import { InMemorySecureKeyStore } from '../testing'

const CLIENT_ENTITY_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const OWNER_BINDING_ID = '11111111-2222-4333-8444-555555555555'
const AUTH_KEY_ID = '99999999-8888-4777-8666-555555555555'

function activeContext() {
  const result = toDeviceRegistrationResult(
    {
      deviceCredentialStatus: 'active',
      ownerBindingId: OWNER_BINDING_ID,
      authKeyId: AUTH_KEY_ID,
      resolvedAt: '2026-08-26T12:00:00Z',
    },
    CLIENT_ENTITY_ID,
  )
  if (result.status !== 'ACTIVE') throw new Error('expected an ACTIVE context')
  return result.context
}

describe('DaaUserContext AuthKey binding', () => {
  it('accepts the AuthKey paired at registration completion', async () => {
    const authKey = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const context = bindAuthKeyToContext(activeContext(), await authKey.thumbprint())

    await expect(assertAuthKeyMatchesContext(context, authKey)).resolves.toBeUndefined()
  })

  it('rejects a different local key before it can use the server-assigned kid', async () => {
    const expected = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const replacement = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
    })
    const context = bindAuthKeyToContext(activeContext(), await expected.thumbprint())

    await expect(assertAuthKeyMatchesContext(context, replacement)).rejects.toThrow(
      'does not match the ACTIVE DaaUserContext',
    )
  })

  it('rejects an unbound decoded context rather than trusting its authKeyId', async () => {
    const authKey = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })

    await expect(assertAuthKeyMatchesContext(activeContext(), authKey)).rejects.toThrow(
      'has no local AuthKey binding',
    )
  })
})

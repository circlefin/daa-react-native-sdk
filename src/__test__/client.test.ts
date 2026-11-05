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

import * as sdk from '../index'
import * as testing from '../testing'
import { createDaaUserClient } from '../api/DaaUserClient'
import { DEVICE_KEY_POLICY, publicApiOriginFor } from '../config'
import { DaaClient } from '../DaaClient'
import { isDaaError } from '../errors'
import type {
  Account,
  AccountListQuery,
  AccountsClient,
  AddressObject,
  AddressObjectRendering,
  CreateAccountRequest,
  CreateTransferAmount,
  CreateTransferDestination,
  CreateTransferRequest,
  CreateTransferRiskSignals,
  CreateTransferSource,
  DaaUserClient,
  Deposit,
  DepositAddressChain,
  DepositAddressListQuery,
  DepositAccountLocation,
  DepositAddressesClient,
  DepositRendering,
  DepositRiskEvaluation,
  DepositsClient,
  DepositSourceLocation,
  DepositStatus,
  DepositType,
  Fee,
  GenerateAddressRequest,
  Page,
  Transaction,
  TransactionAccountLocation,
  TransactionBlockchainLocation,
  TransactionBlockchainLocationRendering,
  TransactionFiatLocation,
  TransactionListQuery,
  TransactionLocation,
  TransactionRendering,
  TransactionStatus,
  TransactionsClient,
  TransactionType,
  Transfer,
  TransferListQuery,
  TransferDestinationAccountLocation,
  TransferDestinationAccountLocationRendering,
  TransferDestinationBlockchainLocation,
  TransferDestinationBlockchainLocationRendering,
  TransferDestinationLocation,
  TransferErrorCode,
  TransferPolicyEvaluation,
  TransferRendering,
  TransfersClient,
  TransferSourceLocation,
  TransferStatus,
  WithdrawalAdjustments,
  WithdrawalDestination,
  WithdrawalDestinationType,
  WithdrawalDetail,
  WithdrawalDetailRendering,
  WithdrawalErrorCode,
  WithdrawalPolicyEvaluation,
  WithdrawalReturn,
  WithdrawalRiskEvaluation,
  WithdrawalsClient,
  WithdrawalStatus,
  WithdrawalSubAccountSweep,
  WithdrawalSweepStatus,
  WithdrawalToAmount,
} from '../index'
import type { DaaTransport } from '../transport/DaaTransport'
import { NO_SIGNING } from './userClientSigning'

type IntegratedPublicModels = readonly [
  Account,
  AccountListQuery,
  Page<Account>,
  AddressObject,
  AddressObjectRendering,
  CreateAccountRequest,
  CreateTransferAmount,
  CreateTransferDestination,
  CreateTransferRequest,
  CreateTransferRiskSignals,
  CreateTransferSource,
  DepositAddressChain,
  DepositAddressListQuery,
  Deposit,
  DepositAccountLocation,
  DepositRendering,
  DepositRiskEvaluation,
  DepositSourceLocation,
  DepositStatus,
  DepositType,
  Fee,
  GenerateAddressRequest,
  Transaction,
  TransactionAccountLocation,
  TransactionBlockchainLocation,
  TransactionBlockchainLocationRendering,
  TransactionFiatLocation,
  TransactionListQuery,
  TransactionLocation,
  TransactionRendering,
  TransactionStatus,
  TransactionType,
  Transfer,
  TransferListQuery,
  TransferDestinationAccountLocation,
  TransferDestinationAccountLocationRendering,
  TransferDestinationBlockchainLocation,
  TransferDestinationBlockchainLocationRendering,
  TransferDestinationLocation,
  TransferErrorCode,
  TransferPolicyEvaluation,
  TransferRendering,
  TransferSourceLocation,
  TransferStatus,
  WithdrawalAdjustments,
  WithdrawalDestination,
  WithdrawalDestinationType,
  WithdrawalDetail,
  WithdrawalDetailRendering,
  WithdrawalErrorCode,
  WithdrawalPolicyEvaluation,
  WithdrawalReturn,
  WithdrawalRiskEvaluation,
  WithdrawalStatus,
  WithdrawalSubAccountSweep,
  WithdrawalSweepStatus,
  WithdrawalToAmount,
]

const transport: DaaTransport = {
  async send() {
    return { status: 200, headers: {}, bodyBytes: null }
  },
}

describe('DaaClient', () => {
  it('rejects a missing appId', () => {
    expect(
      () =>
        new DaaClient({
          appId: '',
          environment: 'sandbox',
          transport,
          keyPolicy: DEVICE_KEY_POLICY,
        }),
    ).toThrow(/appId is required/)
  })

  // The rules themselves are pinned in alias.test.ts; this pins that the
  // constructor applies them, rather than the first AuthKey resolution, which
  // runs only after Social Session has bound the end user.
  it.each([
    ['one character over the 41-character budget', 'a'.repeat(42)],
    ['a character outside the key-namespace charset', 'app/123'],
  ])('rejects an appId with %s at construction', (_label, appId) => {
    let thrown: unknown
    try {
      new DaaClient({ appId, environment: 'sandbox', transport, keyPolicy: DEVICE_KEY_POLICY })
    } catch (err) {
      thrown = err
    }

    expect(isDaaError(thrown) && thrown.detail.kind).toBe('contract_violation')
  })

  it('rejects an unknown environment (runtime allow-list)', () => {
    expect(
      () =>
        new DaaClient({
          appId: 'app-123',
          environment: 'prod' as never,
          transport,
          keyPolicy: DEVICE_KEY_POLICY,
        }),
    ).toThrow(/unknown environment/)
  })

  it('exposes config accessors', () => {
    const client = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
    })
    expect(client.appId).toBe('app-123')
    expect(client.environment).toBe('sandbox')
    expect(client.transport).toBe(transport)
    expect(client.keyPolicy).toBe(DEVICE_KEY_POLICY)
  })

  it('derives the pagination trust anchor from the environment', () => {
    expect(
      Object.freeze({
        sandbox: publicApiOriginFor('sandbox'),
        production: publicApiOriginFor('production'),
      }),
    ).toEqual({
      sandbox: 'https://api-sandbox.circle.com',
      production: 'https://api.circle.com',
    })
  })

  it('offers only the public environments', () => {
    expect(sdk.DAA_ENVIRONMENTS).toEqual(['sandbox', 'production'])
    for (const environment of ['development', 'Production']) {
      expect(
        () =>
          new DaaClient({
            appId: 'app-123',
            environment: environment as never,
            transport,
            keyPolicy: DEVICE_KEY_POLICY,
          }),
      ).toThrow(/unknown environment/)
    }
  })

  it.each([
    'https://api-test.circle.com',
    'https://circle.com',
    'https://a-1.b2.circle.com',
    'https://xn--bcher-kva.circle.com',
    `https://${'a'.repeat(63)}.circle.com`,
    `https://aa.${'a.'.repeat(120)}circle.com`,
  ])('accepts publicApiOrigin %s with sandbox', (publicApiOrigin) => {
    expect(
      () =>
        new DaaClient({
          appId: 'app-123',
          environment: 'sandbox',
          transport,
          keyPolicy: DEVICE_KEY_POLICY,
          publicApiOrigin,
        }),
    ).not.toThrow()
  })

  it.each(['https://api-test.circle.com', 'https://api.circle.com', 'http://x', ''])(
    'refuses publicApiOrigin %p with production, even a valid origin',
    (publicApiOrigin) => {
      expect(
        () =>
          new DaaClient({
            appId: 'app-123',
            environment: 'production',
            transport,
            keyPolicy: DEVICE_KEY_POLICY,
            publicApiOrigin,
          }),
      ).toThrow('DAA: publicApiOrigin cannot be set for production')
    },
  )

  it.each([
    '',
    'http://api-test.circle.com',
    'HTTPS://api-test.circle.com',
    'https://API-TEST.circle.com',
    'https://evil.example',
    'https://circle.com.evil.example',
    'https://evilcircle.com',
    'https://api-test.circle.com/',
    'https://api-test.circle.com/v1',
    'https://api-test.circle.com:443',
    'https://api-test.circle.com:8443',
    'https://api-test.circle.com?x=1',
    'https://api-test.circle.com#x',
    'https://user@api-test.circle.com',
    'https://api-test.circle.com.',
    'https://.circle.com',
    'https://a..circle.com',
    'https://-api.circle.com',
    'https://api-.circle.com',
    'https://api_test.circle.com',
    `https://${'a'.repeat(64)}.circle.com`,
    `https://${'a.'.repeat(122)}circle.com`,
    ' https://api-test.circle.com',
    'https://daa-scä.circle.com',
    'https://api-test.circle.com\n',
    'https://api-test\t.circle.com',
    'https://circle.com\u0000',
    null,
    42,
  ])('refuses publicApiOrigin %p as not a bare https circle.com origin', (publicApiOrigin) => {
    expect(
      () =>
        new DaaClient({
          appId: 'app-123',
          environment: 'sandbox',
          transport,
          keyPolicy: DEVICE_KEY_POLICY,
          publicApiOrigin: publicApiOrigin as never,
        }),
    ).toThrow(
      'DAA: publicApiOrigin must be a bare, lowercase https origin on circle.com or a subdomain',
    )
  })

  it('exposes auth but keeps the authenticated operations surface fail-closed', () => {
    const client = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
    })
    // Prepare is reachable (the login's first call); see `authClient.test.ts`.
    expect(typeof client.auth.prepareSocialLogin).toBe('function')
    // `forUser` needs a `DaaUserContext`, which only an ACTIVE Device Registration
    // Complete produces.
    expect(() => client.forUser({} as never)).toThrow(/ACTIVE DaaUserContext/)
  })
})

describe('DaaUserClient integration', () => {
  it('builds every resource client over the same transport and freezes the surface', async () => {
    const failure = new Error('shared transport')
    const sharedTransport: DaaTransport = {
      async send() {
        throw failure
      },
    }
    const user: DaaUserClient = createDaaUserClient(sharedTransport, 'production', NO_SIGNING)
    const clients: readonly [
      AccountsClient,
      DepositAddressesClient,
      DepositsClient,
      TransactionsClient,
      TransfersClient,
      WithdrawalsClient,
    ] = [
      user.accounts,
      user.depositAddresses,
      user.deposits,
      user.transactions,
      user.transfers,
      user.withdrawals,
    ]
    const publicModelsCompile: IntegratedPublicModels | null = null

    expect(Object.isFrozen(user)).toBe(true)
    expect(publicModelsCompile).toBeNull()
    for (const client of clients) {
      expect(Object.isFrozen(client)).toBe(true)
    }

    // Each client reached the one shared transport: its throw comes back as a
    // transport error with that same throw as the cause.
    const sharedFailure = { detail: { kind: 'transport', retryable: true }, cause: failure }
    await expect(user.accounts.get('acct-1')).rejects.toMatchObject(sharedFailure)
    await expect(
      user.depositAddresses.get('3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'),
    ).rejects.toMatchObject(sharedFailure)
    await expect(user.deposits.get('3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8')).rejects.toMatchObject(
      sharedFailure,
    )
    await expect(user.transactions.list()).rejects.toMatchObject(sharedFailure)
    await expect(user.transfers.get('3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8')).rejects.toMatchObject(
      sharedFailure,
    )
    await expect(
      user.withdrawals.get('3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'),
    ).rejects.toMatchObject(sharedFailure)
  })
})

describe('public surface', () => {
  it('exposes only the approved runtime exports (no signing entry points)', () => {
    const keys = Object.keys(sdk)
      .filter((k) => k !== '__esModule')
      .sort()
    expect(keys).toEqual(
      [
        'DAA_ENVIRONMENTS',
        'DEVICE_KEY_POLICY',
        'DaaClient',
        'DaaError',
        // Passkey SCA: the factory and its error type. No ceremony or signing
        // primitive is exported; the factory only reaches the DaaSca native module.
        'ScaError',
        'createScaClient',
        'fromBase64Url',
        'isDaaError',
        'isScaError',
        'serializeBody',
        'serializeEmptyBody',
        'toBase64Url',
      ].sort(),
    )
  })

  it('does not runtime-export integrated clients or server-attributed model constructors', () => {
    const runtime = sdk as Record<string, unknown>
    for (const name of [
      'AccountsClient',
      'AuthClient',
      'AuthKeyResolution',
      'OwnerAuthKey',
      'PreparedSocialLogin',
      'DepositAddressesClient',
      'DepositAddressListQuery',
      'DepositsClient',
      'TransactionsClient',
      'TransactionListQuery',
      'Transaction',
      'TransactionBlockchainLocation',
      'TransfersClient',
      'WithdrawalsClient',
      'DaaUserClient',
      'AddressObject',
      'CreateAccountRequest',
      'CreateTransferRequest',
      'GenerateAddressRequest',
      'Deposit',
      'Transfer',
      'TransferListQuery',
      'TransferDestinationAccountLocation',
      'TransferDestinationBlockchainLocation',
      'WithdrawalDetail',
      'WithdrawalToAmount',
      'Page',
    ]) {
      expect(runtime[name]).toBeUndefined()
    }
  })

  // A surface lock, not an inventory: `./testing` is the one entry allowed to
  // hand out real runtime capability, so anything appearing here should be a
  // deliberate decision rather than a re-export that drifted in. Adding a name
  // means justifying it.
  it('the ./testing entry exposes only the sanctioned test doubles', () => {
    const keys = Object.keys(testing)
      .filter((k) => k !== '__esModule')
      .sort()
    expect(keys).toEqual([
      // WebCrypto-backed Owner key. Fails closed in a production build.
      'InMemorySecureKeyStore',
    ])
  })

  it('the ./testing entry pulls in neither React nor React Native', () => {
    // A transitive React import here would make this entry unusable from the
    // node environment most backend-adjacent test suites run in.
    for (const name of ['react', 'react-native']) {
      expect(Object.keys(require.cache).some((f) => f.includes(`/node_modules/${name}/`))).toBe(
        false,
      )
    }
  })
})

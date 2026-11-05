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

// Public surface of this package.
//
// The transport boundary, exact-byte serialization, the typed read/write clients
// (types only), and the login ceremony: Prepare, Social Session, Device
// Registration Complete, then `DaaClient.forUser` for an ACTIVE context.
// No generic signing API. Registered-device `signDeviceAuthorization` is
// bridged to native on both platforms. Device Registration Complete sends the
// two-JWS registration proof — `X-Device-Authorization` over the proposed
// AuthKey, plus `X-Registration-Flow-Authorization` over the ephemeral flow
// key committed at Prepare — and both signatures reach native, each through
// its OWN typed seam: the AuthKey signs the device proof through
// `signRegistrationDeviceAuthorization` (a different native function and
// validator from post-activation `signDeviceAuthorization` — see
// `securekey/SecureKey.ts`), and the flow key signs through
// `DaaRegistrationFlowKey.signRegistrationAuthorization`. Tests can also
// finish the ceremony with the WebCrypto flow-key provider and `./testing`
// InMemory AuthKeys.
//
// The Owner-key *interfaces* are exported (they carry no runtime capability and
// are the contract that native/production key stores implement). The concrete
// WebCrypto test double is NOT exported here — it lives behind the `./testing`
// subpath and fails closed in production builds. So raw-byte signing is
// unreachable from `.` on exports-aware resolvers, and gated by a runtime guard
// elsewhere (see SECURITY.md and the `exports` map in package.json).

export { DaaClient } from './DaaClient'

// Passkey SCA (native ceremony through Circle's hosted page). A runtime value
// on purpose: it is the only way to reach the DaaSca native module.
export { createScaClient, isScaError, ScaError } from './sca/ScaClient'
export type {
  ScaCapabilities,
  ScaClient,
  ScaConfig,
  ScaEnvironment,
  ScaErrorCode,
} from './sca/ScaClient'

// The typed API surface and its models are exported as **types only**. That is
// what keeps a consumer from fabricating server-attributed data: there is no
// runtime constructor for `Account`, `Money`, `BusinessPii`, or `Address`
// anywhere on this entry, and the factory that builds them
// (`api/DaaUserClient.createDaaUserClient`) is not exported either. Every
// instance a caller can hold came from a response this SDK decoded. The models
// also carry `#` private fields, so an object literal cannot be *typed* as one
// of them either.
//
// The mixed prefixing is deliberate. The SDK contract states this surface in
// TypeScript, so for this SDK those are the names rather than an idiomatic
// rendering of them: `DaaClient`, `DaaUserClient`, `DaaTransport`,
// `DaaSdkConfiguration`, `DaaUserContext`, and `DaaSdkError` carry the prefix;
// the resources and sub-clients — `Account`, `AccountsClient`, `Page` — do not.
// Names the contract does not mention (`Money`, `BusinessPii`, `Address`)
// follow its convention for resources.
//
// TypeScript has no namespace to lean on the way the natives do, so a consumer
// imports into a flat scope; every unprefixed name here is type-only, and a
// collision with an app's own `Account` is resolved at the import site with `as`.
export type { AuthClient } from './api/AuthClient'
export type { AccountListQuery, AccountsClient } from './api/AccountsClient'
export type { AccountLimitsClient, AccountLimitsUsageQuery } from './api/AccountLimitsClient'
export type { DepositAddressListQuery, DepositAddressesClient } from './api/DepositAddressesClient'
export type { DepositListQuery, DepositsClient } from './api/DepositsClient'
export type { TransactionListQuery, TransactionsClient } from './api/TransactionsClient'
export type { TransferListQuery, TransfersClient } from './api/TransfersClient'
export type { WithdrawalListQuery, WithdrawalsClient } from './api/WithdrawalsClient'
export type { FiatAccountsClient } from './api/FiatAccountsClient'
export type {
  PublicAccountId,
  WireFiatAccountListQuery,
  WireFiatAccountsClient,
  WireInstructionQuery,
} from './api/WireFiatAccountsClient'
export type { AchFiatAccountListQuery, AchFiatAccountsClient } from './api/AchFiatAccountsClient'
export type { DaaUserClient } from './api/DaaUserClient'
export type {
  DaaUserContext,
  DeviceContext,
  DeviceRegistrationResult,
} from './models/DaaUserContext'
export type { PendingDeviceRegistration } from './models/PendingDeviceRegistration'
export type {
  Account,
  AccountPurpose,
  AccountRendering,
  AccountStatus,
  AccountType,
  CustodyType,
} from './models/Account'
export type { CreateAccountRequest } from './models/CreateAccountRequest'
export type {
  AccountLimitsUsage,
  AccountLimitsUsageItem,
  AccountLimitsUsageRendering,
  AccountLimitsUsageResourceType,
  LimitsUsageAssetType,
  LimitsUsageComparisonType,
  LimitsUsageOperation,
  LimitsUsageUnit,
  LimitsUsageWindow,
} from './models/AccountLimitsUsage'
export type {
  CreateTransferAmount,
  CreateTransferDestination,
  CreateTransferRequest,
  CreateTransferRiskSignals,
  CreateTransferSource,
} from './models/CreateTransferRequest'
export type { Address, BusinessPii } from './models/BusinessPii'
export type { AddressObject, AddressObjectRendering } from './models/AddressObject'
export type { DepositAddressChain, GenerateAddressRequest } from './models/GenerateAddressRequest'
export type {
  Deposit,
  DepositAccountLocation,
  DepositRendering,
  DepositRiskEvaluation,
  DepositSourceLocation,
  DepositStatus,
  DepositType,
} from './models/Deposit'
export type { DepositSummary, DepositSummaryRendering } from './models/DepositSummary'
export type { Money } from './models/Money'
export type { Page } from './models/Page'
export type { PreparedSocialLogin } from './models/PreparedSocialLogin'
export type {
  Transaction,
  TransactionAccountLocation,
  TransactionBlockchainLocation,
  TransactionBlockchainLocationRendering,
  TransactionFiatLocation,
  TransactionLocation,
  TransactionRendering,
  TransactionStatus,
  TransactionType,
} from './models/Transaction'
export type {
  Fee,
  Transfer,
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
} from './models/Transfer'
export type {
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
} from './models/Withdrawal'
export type {
  CreateWithdrawalAmount,
  CreateWithdrawalDestination,
  CreateWithdrawalRequest,
  CreateWithdrawalRiskSignals,
  CreateWithdrawalSource,
  CreateWithdrawalToAmount,
} from './models/CreateWithdrawalRequest'
export type { BankAddress, BillingDetails, FiatAccountStatus } from './models/FiatAccount'
export type {
  TransferTypeInfo,
  Wire,
  WireInstruction,
  WireInstructionBeneficiary,
  WireInstructionBeneficiaryBank,
  WireSummary,
} from './models/Wire'
export type {
  ACH,
  ACHInstruction,
  ACHInstructionBeneficiary,
  ACHInstructionBeneficiaryBank,
} from './models/Ach'

export { DAA_ENVIRONMENTS, DEVICE_KEY_POLICY } from './config'
export type { DaaEnvironment, DaaSdkConfiguration, DeviceKeyPolicy } from './config'
export type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from './transport/DaaTransport'
export type { DaaSdkError } from './errors'
// Structured error thrown by the SDK; callers narrow with `isDaaError` and read
// `err.detail.kind`.
export { DaaError, isDaaError } from './errors'
export type {
  AuthKeyResolution,
  OwnerAuthKey,
  OwnerKeyIdentity,
  SecureKeyStore,
} from './securekey/SecureKey'

// Exact-byte serialization utilities.
export { serializeBody, serializeEmptyBody } from './crypto/serialization'
export { toBase64Url, fromBase64Url } from './crypto/base64url'

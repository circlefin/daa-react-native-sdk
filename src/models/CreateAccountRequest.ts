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

// The body of a signed account create.
//
// **Shaped from the Owner-authorization registry, not from the OpenAPI.** The
// digest-pinned registry is what DAA validates the signed bytes against,
// property by property, with `additionalProperties: false`; the OpenAPI
// describes what the HTTP endpoint documents. Where the two disagree the registry decides what
// may be sent, because a body the registry rejects never reaches the endpoint
// the OpenAPI describes.
//
// They do disagree here, in more than one place worth naming. The registry's
// `create_account` schema lists `clientEntityId` as an optional property,
// while the contract's `SelfCustodyAccountCreationRequest` marks it required,
// and a non-custodial account requires it outright — resolved by the consuming
// application's authenticated backend, included in the exact signed body, and
// checked against the active Owner binding before anything else persists.
// Since the registry pins `custodyType` to the single value `self`, every
// signed create is a self-custody create, which is exactly the shape the
// contract requires it on. So it is required in this type: the registry
// describes the outer bound of what DAA would accept, not what a
// conforming SDK should send, and this SDK holds itself to the stricter rule
// rather than the more permissive one.
//
// `type` and `purpose` follow the identical pattern. The registry's
// `create_account` schema types both as open strings, but the contract's
// `SelfCustodyAccountCreationRequest` narrows each to the single literal a
// self-custody create can carry — `third_party` and `custody` — and DAA rejects
// any other value outright. Since this type is exclusively the self-custody
// create body, it holds itself to the contract's single literal for each rather
// than the registry's wider set.
//
// `blockchain` is optional, and this SDK does not require it: DAA selects the
// home chain when it is omitted and provisions on `ARC`. The registry types it
// as a plain optional string, and the public API docs document it as optional.

/**
 * Body for creating a self-custody DAA account.
 *
 * Every field is checked before the body is serialized, and the serialized
 * bytes are the ones signed and sent. An unrecognized property is rejected
 * rather than dropped: the registry schema refuses additional properties, so a
 * misspelled `blockChain` is a request DAA would reject, and silently
 * discarding it would instead create an account on the wrong home chain.
 */
export type CreateAccountRequest = Readonly<{
  /**
   * Identifies this account-creation attempt. Persist it before sending and
   * never reuse it with different body bytes — the authorization JWS carries
   * this same value as its `idempotency_key` claim, so a reused key with
   * changed bytes is a different signed request under an old identity.
   */
  idempotencyKey: string
  /**
   * The end-user sub-entity the account is for. Required: the registry itself
   * would admit omitting it, but the public contract requires it for a
   * self-custody create, and DAA checks it against the active Owner binding
   * before anything persists. See the file note.
   */
  clientEntityId: string
  /** The registry admits one value: this is the self-custody create. */
  custodyType: 'self'
  /**
   * Whether the account is held for the entity itself or on behalf of
   * another. The registry types this as an open string, but the contract
   * narrows a self-custody create to the single literal `third_party` —
   * non-custodial accounts are always end-user accounts — and DAA rejects
   * any other value. See the file note.
   */
  type: 'third_party'
  /**
   * What the account is for. The registry types this as an open string, but
   * the contract narrows a self-custody create to the single literal
   * `custody`, and DAA rejects any other value. See the file note.
   */
  purpose: 'custody'
  /**
   * Caller-supplied label. Required by the registry, and so never omitted.
   * The contract caps it at 255 characters; this SDK checks that bound
   * locally so an oversized label fails before a device-authorization
   * ceremony and idempotency key are spent on a request the service would
   * reject anyway.
   */
  description: string
  /**
   * The account's immutable home chain. Optional: DAA resolves and persists
   * `ARC` when it is omitted, and that default is the service's to apply
   * rather than one this SDK sends on its behalf. See the file note. A plain
   * string rather than a closed set, matching `Account.blockchain`: the
   * registry types it `string`, and new chains ship without an SDK release.
   */
  blockchain?: string
}>

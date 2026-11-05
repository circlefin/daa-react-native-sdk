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

import { REDACTED } from './redaction'

/**
 * An amount in a currency, as the DAA API reports it (`Money`).
 *
 * `currency` is a `string`, not a closed union, deliberately. The OpenAPI
 * schema types it as an enum of twenty-two currencies — BIF, BYR, CLP,
 * CNH, EUR, IDR, IQD, IRR, JOD, KPW, LAK, LBP, MKD, MMK, MNT, MUR, NOK, PKR,
 * RSD, SLL, SYP, UGX — which does **not** include USD. That enum does not list
 * every currency the service returns, and a client that turned it into a
 * closed type would reject the balance this SDK exists to report.
 *
 * `amount` is the **exact decimal literal the service sent**, carried as a
 * string. JavaScript has one number type and it is an IEEE-754 double, so a
 * balance sent as `1234567890123456.78` comes back a different value with
 * nothing to indicate it changed — the same reason the Kotlin model refuses a
 * `Double`. `JSON.parse` performs that conversion before any code here can see
 * the token, so there is no way to recover an exact value from a JSON number
 * after the fact.
 *
 * The SDK does not try to. The service sends this field as a plain decimal JSON
 * **string**, so the exact decimal arrives untouched. An `amount` that ever
 * arrives as a JSON number is **rejected** as a malformed response rather than
 * coerced: by then it has already been rounded, and reporting it would mean
 * handing back a balance the service never sent. Its
 * grammar is checked on the way in (`wire/jsonNumber.ts`), since nothing else
 * verifies that a string field holds a number.
 *
 * A caller doing arithmetic should hand `amount` to a decimal library;
 * `Number(amount)` reintroduces exactly the rounding this avoids.
 *
 * Not constructible by a consumer: this class is exported from `index.ts` as a
 * **type only**, so no runtime constructor reaches the public entry, and the
 * private `#amount` field makes the type nominal so an object literal cannot be
 * typed as a `Money` either. Every instance a caller holds came from a
 * response this SDK decoded.
 *
 * **No default rendering prints the amount.** `Account` reduces its balances
 * to a count precisely so a logged account does not carry holdings, and that is
 * worth nothing if logging one balance prints it anyway. `amount` is reached
 * through a prototype accessor rather than an own property, so it is absent from
 * `Object.keys`, `JSON.stringify`, `{ ...money }`, `for...in`, and the object
 * inspectors that drive `console.log`. The service excludes the same class of
 * value from its own rendering.
 */
export class Money {
  /** ISO 4217 code. Not constrained to a known set — see the class note. */
  readonly currency: string

  readonly #amount: string

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(amount: string, currency: string) {
    this.#amount = amount
    this.currency = currency
    Object.freeze(this)
  }

  /** The amount, exactly as the service sent it. See the class note. */
  get amount(): string {
    return this.#amount
  }

  /** `JSON.stringify` renders the currency and says the amount was withheld. */
  toJSON(): { readonly amount: string; readonly currency: string } {
    return { amount: REDACTED, currency: this.currency }
  }

  /** The currency is not sensitive; the amount is. */
  toString(): string {
    return `Money(amount=${REDACTED}, currency=${this.currency})`
  }
}

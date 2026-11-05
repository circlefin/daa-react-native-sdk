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

// The JSON number grammar, applied to values that arrive as text.

/**
 * RFC 8259's number grammar.
 *
 * The service sends `Money.amount` as a plain decimal JSON **string**, not a
 * number. So the exact decimal survives
 * `JSON.parse` untouched, and nothing on the way in checks that the text is a
 * number at all — the OpenAPI's `type: number` describes the schema, not the
 * wire.
 *
 * That makes this the **only** check on an amount rather than a second one, which
 * is why it lives on its own rather than beside a decoder.
 */
export const JSON_NUMBER = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/

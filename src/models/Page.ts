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

type PageLoader<T> = () => Promise<Page<T>>

/** A frozen collection page with trusted navigation to adjacent pages. */
export class Page<T> {
  readonly items: readonly T[]
  readonly #next: PageLoader<T> | null
  readonly #previous: PageLoader<T> | null

  /** @internal Constructed only by a typed collection client. */
  constructor(items: readonly T[], next: PageLoader<T> | null, previous: PageLoader<T> | null) {
    this.items = Object.freeze([...items])
    this.#next = next
    this.#previous = previous
    Object.freeze(this)
  }

  /** Load the following page, or return `null` when the API supplied no link. */
  async next(): Promise<Page<T> | null> {
    return this.#next === null ? null : this.#next()
  }

  /** Load the preceding page, or return `null` when the API supplied no link. */
  async previous(): Promise<Page<T> | null> {
    return this.#previous === null ? null : this.#previous()
  }

  toJSON(): Readonly<{ items: readonly T[] }> {
    return Object.freeze({ items: this.items })
  }
}

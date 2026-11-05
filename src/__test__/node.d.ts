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

// Minimal ambient declarations for the Node built-ins the tests need, and
// nothing else. Each is declared narrower than the real API so
// no test can reach past what it uses. The callers:
//
//   - the conformance fixture loader, which reads a file off disk
//     (`__dirname` + `node:fs`)
//   - the redaction tests, which assert against what `console.log` prints
//     (`node:util`)
//
// The repo has no declared `@types/node` and `tsconfig.json` limits `types` to
// `["jest"]` on purpose: production and native code must not be able to reach a
// Node API. Widening the global type set — or taking a dependency to get these few functions — would weaken
// that.
// These declarations are ambient, so despite living here they are visible to
// every file `tsconfig.json` includes — all of `src`, not just `src/__test__/`.
// `tsconfig.build.json` and `package.json#files` exclude `src/__test__/`, which
// keeps them out of a consumer's build but does not stop production code
// type-checking against them. The `no-restricted-imports` rule in
// `eslint.config.js` is what actually holds the invariant, at the lint step.

declare const __dirname: string

declare module 'node:fs' {
  export function readFileSync(path: string): Uint8Array
}

// `util.inspect` is what Node's `console.log` renders an object with, so the
// redaction tests assert against it rather than only against `JSON.stringify`.
declare module 'node:util' {
  export function inspect(
    value: unknown,
    options?: { depth?: number | null; showHidden?: boolean; getters?: boolean },
  ): string
}

// `require.cache` keys are the absolute paths of every module loaded so far.
// One test-only caller: the `./testing` entry asserts that importing it does not
// transitively pull in React, which is what keeps the test doubles usable from a
// plain node test environment. Declared as the narrowest thing that answers "was
// this loaded?" — a set of paths — rather than the real
// `Record<string, NodeModule>`, so nothing can reach a loaded module through it.
declare const require: {
  cache: Record<string, unknown>
}

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

// Flat ESLint config (ESLint 9). Formatting is owned by Prettier, so
// eslint-config-prettier disables any stylistic rules that would conflict.
const tseslint = require('typescript-eslint')
const prettier = require('eslint-config-prettier')
const reactHooks = require('eslint-plugin-react-hooks')

module.exports = tseslint.config(
  { ignores: ['**/build/**', 'coverage/**', '**/node_modules/**', 'android/**', 'ios/**'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [...tseslint.configs.recommended],
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
    },
  },
  // Production and native code must not reach a Node API. `tsconfig.json`
  // narrows `types` to `["jest"]` for that reason, but the ambient declarations
  // in `src/__test__/node.d.ts` are program-global and would otherwise let a
  // `node:fs` import in `src/crypto/` or `src/securekey/` pass `check:type`.
  // Excluding `src/__test__/` from `tsconfig.build.json` only moves that
  // failure to the build step; this keeps it at the lint step, where the
  // message says what the rule is.
  {
    files: ['src/**/*.{ts,tsx}', 'packages/*/src/**/*.{ts,tsx}'],
    ignores: ['src/__test__/**', 'packages/*/src/__test__/**'],
    rules: {
      // `paths` matches an exact specifier; `patterns` is a glob. The bare
      // built-ins have to go in `paths`, because as a pattern `crypto` also
      // matches this repo's own `../crypto/base64url`.
      'no-restricted-imports': ['error', { paths: ['fs', 'path', 'crypto'], patterns: ['node:*'] }],
    },
  },
  // TypeScript's `private` keyword is a compile-time annotation only — `tsc`
  // erases it at build time (this repo targets ES2020 with no downlevel
  // transform), leaving an ordinary callable/readable member on the
  // prototype. Scoped to all of `src/`, not just `src/api/` and
  // `src/securekey/`: `DaaClient` (`src/DaaClient.ts`) is the SDK's actual
  // public entry point — more public than `AuthClient`, which is only
  // reachable via `DaaClient.auth` — so an erased `private` field or method
  // anywhere in production source is a candidate public surface, not just in
  // the two directories that hold the signing/key-access primitives
  // directly. Use ECMAScript `#` private fields and methods instead, which
  // are enforced at runtime and cannot be erased by the compiler.
  // `src/__test__/` is excluded: erasure in a test double carries no risk,
  // and it is where the repo's ordinary TS `private` constructor parameters
  // legitimately live (recording fixtures, in-memory doubles).
  {
    files: ['src/**/*.{ts,tsx}', 'packages/*/src/**/*.{ts,tsx}'],
    ignores: ['src/__test__/**', 'packages/*/src/__test__/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "MethodDefinition[accessibility='private']",
          message:
            "TypeScript 'private' is erased at build time. Use an ECMAScript '#' private method instead.",
        },
        {
          selector: "PropertyDefinition[accessibility='private']",
          message:
            "TypeScript 'private' is erased at build time. Use an ECMAScript '#' private field instead.",
        },
        {
          selector: "TSParameterProperty[accessibility='private']",
          message:
            "TypeScript 'private' parameter properties are erased at build time. Declare a '#' private field and assign it in the constructor body instead.",
        },
      ],
    },
  },
  // The harness's config plugins and their tests are load-bearing JavaScript.
  // The TypeScript block above does not match these files, so this block gives
  // them a small core-rule set. It is deliberately not
  // `tseslint.configs.recommended`: those are TypeScript rules, and keeping
  // `example/` out of the TypeScript program is the reason these files are
  // JavaScript in the first place.
  //
  // Scoped to `plugins/` rather than all of `example/`: `index.js` is an ES
  // module (Metro/Babel own it, and `sourceType: 'commonjs'` would fail to parse
  // its `import`), and `example/android/` and `example/ios/` are prebuild output.
  //
  // Node and Jest globals have to be declared for `no-undef`, because flat
  // config supplies only the ES built-ins.
  {
    files: ['example/plugins/**/*.js'],
    languageOptions: {
      sourceType: 'commonjs',
      globals: {
        __dirname: 'readonly',
        afterEach: 'readonly',
        beforeEach: 'readonly',
        console: 'readonly',
        describe: 'readonly',
        expect: 'readonly',
        it: 'readonly',
        jest: 'readonly',
        module: 'writable',
        process: 'readonly',
        require: 'readonly',
      },
    },
    rules: {
      'no-undef': 'error',
      'no-unused-vars': 'error',
    },
  },
  prettier,
)

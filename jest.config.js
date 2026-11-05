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

const fs = require('fs')
const path = require('path')

/**
 * Separate projects, deliberately.
 *
 * The DAA core is plain TypeScript with no React in it, and its several hundred
 * tests run in a bare node environment in a couple of seconds. The onboarding
 * widget (`packages/onboarding`, its own npm package) needs React Native's Babel
 * transform, its jest preset, and a DOM-ish renderer — all of which are slower and
 * none of which the core has any use for. Splitting them keeps the core suite
 * fast, and keeps a React Native transform from being imposed on files that do
 * not need it. Onboarding's own React-free
 * logic (the machine, decoders, launchers, poll loop) runs under ts-jest in node,
 * like the core.
 *
 * A project or root is added only when its directory exists. Jest fails at
 * startup on a root that does not.
 */

const exists = (dir) => fs.existsSync(path.join(__dirname, dir))

const ONBOARDING = '<rootDir>/packages/onboarding'

/** @type {import('jest').Config} */
const core = {
  displayName: 'core',
  preset: 'ts-jest',
  testEnvironment: 'node',
  // `example/plugins` is a second root rather than a second Jest project or a
  // runner of its own under `example/`: the config-plugin tests need no Expo
  // install and no build step, so folding them in here means `yarn test:ci`
  // covers them, with no new script, workflow, or lockfile to keep in step.
  roots: ['<rootDir>/src', ...(exists('example/plugins') ? ['<rootDir>/example/plugins'] : [])],
  // The SDK's tests are TypeScript; the harness's config plugins and their
  // tests are JavaScript, because Expo requires the plugins by path at prebuild
  // time and `example/` is outside the TypeScript program on purpose.
  testMatch: ['**/__test__/**/*.test.ts', '**/__test__/**/*.test.js'],
  moduleNameMapper: {
    // `expo` is an optional peer dependency and is installed only in
    // `example/node_modules`, so the plugins' own import cannot resolve from
    // here. See example/plugins/__test__/support/expoConfigPlugins.js.
    '^expo/config-plugins$': '<rootDir>/example/plugins/__test__/support/expoConfigPlugins.js',
  },
  setupFiles: ['<rootDir>/jest.setup.js'],
  clearMocks: true,
}

/** @type {import('jest').Config} */
const onboarding = {
  displayName: 'onboarding',
  testEnvironment: 'node',
  roots: [`${ONBOARDING}/src`],
  testMatch: ['**/__test__/**/*.test.ts'],
  // The package has its own tsconfig (its `include` is its own `src`), so point
  // ts-jest at it rather than letting it pick up the root one.
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: `${ONBOARDING}/tsconfig.json` }],
  },
  clearMocks: true,
}

/** @type {import('jest').Config} */
const onboardingUi = {
  displayName: 'onboarding-ui',
  // Carries the `react-native` moduleNameMapper this project needs. Jest MERGES a
  // preset's mapper into the project's rather than replacing it (`setupPreset` in
  // jest-config's normalize), so there is nothing to re-declare here — a local
  // `moduleNameMapper` would only need to name the entries it ADDS.
  preset: '@react-native/jest-preset',
  roots: [`${ONBOARDING}/src`],
  testMatch: ['**/__test__/**/*.test.tsx'],
  setupFilesAfterEnv: [`${ONBOARDING}/jest.setup.js`],
  clearMocks: true,
}

module.exports = {
  projects: [core, ...(exists('packages/onboarding') ? [onboarding, onboardingUi] : [])],
}

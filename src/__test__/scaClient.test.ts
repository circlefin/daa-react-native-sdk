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

import { createScaClient, isScaError, mapNativeScaError, ScaError } from '../sca/ScaClient'
import type { ScaConfig } from '../sca/ScaClient'

const config: ScaConfig = {
  environment: 'sandbox',
  redirectUri: 'https://app.example.com/sca/callback',
}

// The fixed `message` the SDK sets for each code.
const MESSAGE = {
  Cancelled: 'The SCA ceremony was cancelled',
  Expired: 'The SCA ceremony deadline passed',
  Unsupported: 'This device or app cannot run the SCA ceremony',
  AlreadyEnrolled: 'A passkey is already enrolled on this authenticator',
  Protocol: 'The SCA ceremony failed with a protocol error',
  Transport: 'The SCA ceremony failed on a transport error',
  InvalidConfiguration: 'The SCA configuration was rejected',
  CeremonyInProgress: 'Another SCA ceremony is still open',
  NativeModuleUnavailable: 'The DaaSca native module is not linked in this build',
} as const

function nativeError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code })
}

function fakeNative(
  overrides: Partial<Record<'approve' | 'enroll' | 'capabilities', jest.Mock>> = {},
) {
  return {
    approve: overrides.approve ?? jest.fn(async () => '{"id":"assertion"}'),
    enroll: overrides.enroll ?? jest.fn(async () => '{"id":"registration"}'),
    capabilities:
      overrides.capabilities ??
      jest.fn(async () => ({
        protocolVersion: 1,
        surface: 'customTab',
        callbackReady: true,
        callbackVerified: null,
        callbackTaskIsolated: true,
        platformPasskeys: true,
      })),
  }
}

describe('createScaClient', () => {
  it('passes the frozen config and frame token to native and returns the text unchanged', async () => {
    const native = fakeNative()
    const client = createScaClient(config, native)

    await expect(client.approve('token-1')).resolves.toBe('{"id":"assertion"}')
    await expect(client.enroll('token-2')).resolves.toBe('{"id":"registration"}')

    expect(native.approve).toHaveBeenCalledWith(config, 'token-1')
    expect(native.enroll).toHaveBeenCalledWith(config, 'token-2')
    expect(Object.isFrozen(client.config)).toBe(true)
  })

  it('refuses an unsupported environment or a missing redirect URI up front', () => {
    for (const bad of [
      { ...config, environment: 'not-an-environment' },
      { ...config, environment: 'Sandbox' },
      { ...config, redirectUri: '' },
    ]) {
      expect(() => createScaClient(bad as ScaConfig, fakeNative())).toThrow(
        expect.objectContaining({ code: 'InvalidConfiguration' }),
      )
    }
  })

  it('refuses an empty frame token without calling native', async () => {
    const native = fakeNative()
    await expect(createScaClient(config, native).approve('')).rejects.toMatchObject({
      code: 'InvalidConfiguration',
    })
    expect(native.approve).not.toHaveBeenCalled()
  })

  it('rejects a second ceremony while one is open and leaves the open one alone', async () => {
    let finish: (value: string) => void = () => {}
    const native = fakeNative({
      approve: jest.fn(() => new Promise<string>((resolve) => (finish = resolve))),
    })
    const client = createScaClient(config, native)

    const first = client.approve('token-1')
    await expect(client.enroll('token-2')).rejects.toMatchObject({ code: 'CeremonyInProgress' })
    await expect(client.approve('token-3')).rejects.toMatchObject({ code: 'CeremonyInProgress' })
    finish('done')

    await expect(first).resolves.toBe('done')
    expect(native.enroll).not.toHaveBeenCalled()
    expect(native.approve).toHaveBeenCalledTimes(1)

    native.approve.mockResolvedValueOnce('again')
    await expect(client.approve('token-4')).resolves.toBe('again')
  })

  it('frees the slot after a failure', async () => {
    const native = fakeNative({
      approve: jest
        .fn()
        .mockRejectedValueOnce(nativeError('SCA_CANCELLED', 'x'))
        .mockResolvedValue('{"id":"assertion"}'),
    })
    const client = createScaClient(config, native)

    await expect(client.approve('t')).rejects.toMatchObject({ code: 'Cancelled' })
    await expect(client.approve('t')).resolves.toBe('{"id":"assertion"}')
  })

  it('maps every native code to the shared vocabulary, with the reason', async () => {
    const cases: [string, string, keyof typeof MESSAGE, string | null][] = [
      ['SCA_CANCELLED', 'The ceremony was cancelled', 'Cancelled', null],
      ['SCA_EXPIRED', 'The ceremony deadline passed', 'Expired', null],
      ['SCA_UNSUPPORTED:NoAllowedBrowser', 'no allowed browser', 'Unsupported', 'NoAllowedBrowser'],
      ['SCA_UNSUPPORTED:CallbackNotRouted', 'not routed', 'Unsupported', 'CallbackNotRouted'],
      ['SCA_UNSUPPORTED:SessionUnavailable', 'no window', 'Unsupported', 'SessionUnavailable'],
      ['SCA_UNSUPPORTED:PasskeyUnavailable', 'no passkeys', 'Unsupported', 'PasskeyUnavailable'],
      ['SCA_ALREADY_ENROLLED', 'already', 'AlreadyEnrolled', null],
      ['SCA_PROTOCOL:StateMismatch', 'the callback did not belong', 'Protocol', 'StateMismatch'],
      ['SCA_PROTOCOL:InvalidFrameToken', 'frameToken is too long', 'Protocol', 'InvalidFrameToken'],
      ['SCA_PROTOCOL', 'bad callback', 'Protocol', null],
      ['SCA_TRANSPORT', 'verification timed out', 'Transport', null],
      ['SCA_INVALID_CONFIGURATION', 'invalidRedirectURI', 'InvalidConfiguration', null],
      ['SCA_CEREMONY_IN_PROGRESS', 'open', 'CeremonyInProgress', null],
      ['SOMETHING_ELSE', 'surprise', 'Protocol', null],
    ]
    for (const [nativeCode, message, code, reason] of cases) {
      const native = fakeNative({
        approve: jest.fn().mockRejectedValue(nativeError(nativeCode, message)),
      })
      const err = await createScaClient(config, native)
        .approve('t')
        .catch((e: unknown) => e)
      expect(isScaError(err)).toBe(true)
      expect(err).toMatchObject({ code, reason, message: MESSAGE[code] })
    }
  })

  it('keeps the reason when Expo wraps an async rejection', async () => {
    // The shape Expo produces for an async function: its own message with the
    // native exception as the cause, and the native exception's code unchanged.
    const wrapped = nativeError(
      'SCA_UNSUPPORTED:SessionUnavailable',
      "Calling the 'approve' function has failed\n→ Caused by: No session could be presented",
    )
    const native = fakeNative({ approve: jest.fn().mockRejectedValue(wrapped) })

    await expect(createScaClient(config, native).approve('t')).rejects.toMatchObject({
      code: 'Unsupported',
      reason: 'SessionUnavailable',
      message: MESSAGE.Unsupported,
    })

    const nested = nativeError(
      'SCA_PROTOCOL:StateMismatch',
      "Calling the 'enroll' function has failed\n→ Caused by: outer\n→ Caused by: The callback did not belong to this ceremony",
    )
    expect(mapNativeScaError(nested)).toMatchObject({
      code: 'Protocol',
      reason: 'StateMismatch',
      message: MESSAGE.Protocol,
    })
  })

  it('reads the code from the tagged message when the rejection has none (iOS)', async () => {
    // The shape observed on iOS: no `code`, and Expo's wrapped message.
    const cases: [string, keyof typeof MESSAGE, string | null][] = [
      ['[SCA_CANCELLED] The ceremony was cancelled', 'Cancelled', null],
      ['[SCA_EXPIRED] The ceremony deadline passed', 'Expired', null],
      [
        '[SCA_ALREADY_ENROLLED] This end user already has a passkey on this authenticator.',
        'AlreadyEnrolled',
        null,
      ],
      ['[SCA_CEREMONY_IN_PROGRESS] Another SCA ceremony is still open', 'CeremonyInProgress', null],
      [
        '[SCA_UNSUPPORTED:SessionUnavailable] No session could be presented',
        'Unsupported',
        'SessionUnavailable',
      ],
      ['[SCA_NOT_A_CODE] surprise', 'Protocol', null],
      ['The ceremony deadline passed', 'Protocol', null],
    ]
    for (const [inner, code, reason] of cases) {
      const rejection = new Error(
        `Calling the 'approve' function has failed\n→ Caused by: ${inner}`,
      )
      const native = fakeNative({ approve: jest.fn().mockRejectedValue(rejection) })
      const err = await createScaClient(config, native)
        .approve('t')
        .catch((e: unknown) => e)
      expect(err).toMatchObject({ code, reason, message: MESSAGE[code] })
    }
  })

  it('prefers a known code over the tag', () => {
    expect(
      mapNativeScaError(nativeError('SCA_EXPIRED', '[SCA_EXPIRED] The ceremony deadline passed')),
    ).toMatchObject({ code: 'Expired', reason: null, message: MESSAGE.Expired })
    expect(
      mapNativeScaError(nativeError('SCA_CANCELLED', '[SCA_EXPIRED] The ceremony deadline passed')),
    ).toMatchObject({ code: 'Cancelled' })
    expect(
      mapNativeScaError(
        nativeError('ERR_FUNCTION_CALL', '[SCA_CANCELLED] The ceremony was cancelled'),
      ),
    ).toMatchObject({ code: 'Cancelled', message: MESSAGE.Cancelled })
  })

  it('never puts native text in the message, and keeps it only on a non-enumerable cause', async () => {
    const secret = 'keychain item 0x7f3a at /private/var/containers/internal-detail'
    const rejections: unknown[] = [
      nativeError('SCA_PROTOCOL', secret),
      nativeError(
        'SCA_UNSUPPORTED:SessionUnavailable',
        `[SCA_UNSUPPORTED:SessionUnavailable] ${secret}`,
      ),
      nativeError('SOMETHING_ELSE', secret),
      new Error(`Calling the 'approve' function has failed\n→ Caused by: [SCA_EXPIRED] ${secret}`),
      new Error(secret),
    ]
    for (const rejection of rejections) {
      const native = fakeNative({ approve: jest.fn().mockRejectedValue(rejection) })
      const err = (await createScaClient(config, native)
        .approve('t')
        .catch((e: unknown) => e)) as ScaError

      expect(isScaError(err)).toBe(true)
      expect(err.message).not.toContain('keychain')
      expect(String(err)).not.toContain('keychain')
      expect(err.cause).toBe(rejection)
      expect(Object.getOwnPropertyDescriptor(err, 'cause')?.enumerable).toBe(false)
      expect(Object.keys(err)).not.toContain('cause')
      expect(JSON.stringify(err)).not.toContain('keychain')
    }
  })

  it('drops a reason that is not a plain name', () => {
    const err = mapNativeScaError(
      nativeError('SCA_UNSUPPORTED:no browser at /data/app/internal', 'x'),
    )
    expect(err).toMatchObject({ code: 'Unsupported', reason: null, message: MESSAGE.Unsupported })
  })

  it('sets the fixed message on the errors the SDK raises itself', async () => {
    await expect(createScaClient(config, null).approve('t')).rejects.toMatchObject({
      message: MESSAGE.NativeModuleUnavailable,
    })
    let finish: (value: string) => void = () => {}
    const native = fakeNative({
      approve: jest.fn(() => new Promise<string>((resolve) => (finish = resolve))),
    })
    const client = createScaClient(config, native)
    const first = client.approve('t1')
    await expect(client.approve('t2')).rejects.toMatchObject({
      message: MESSAGE.CeremonyInProgress,
    })
    finish('done')
    await first
  })

  it('fails closed on codes that only exist on the object prototype', () => {
    for (const key of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      expect(mapNativeScaError(nativeError(key, 'x')).code).toBe('Protocol')
    }
  })

  it('normalizes capabilities and maps their failures', async () => {
    const client = createScaClient(config, fakeNative())
    await expect(client.capabilities()).resolves.toEqual({
      protocolVersion: 1,
      surface: 'customTab',
      callbackReady: true,
      callbackVerified: null,
      callbackTaskIsolated: true,
      platformPasskeys: true,
    })

    const failing = createScaClient(
      config,
      fakeNative({
        capabilities: jest.fn().mockRejectedValue(nativeError('SCA_INVALID_CONFIGURATION', 'bad')),
      }),
    )
    await expect(failing.capabilities()).rejects.toMatchObject({ code: 'InvalidConfiguration' })
  })

  it('reports a missing native module as NativeModuleUnavailable', async () => {
    const client = createScaClient(config, null)
    await expect(client.approve('t')).rejects.toMatchObject({ code: 'NativeModuleUnavailable' })
    await expect(client.capabilities()).rejects.toMatchObject({ code: 'NativeModuleUnavailable' })
  })

  it('passes an existing ScaError through unchanged', () => {
    const original = new ScaError('Expired', 'x')
    expect(mapNativeScaError(original)).toBe(original)
    expect(original.cause).toBeUndefined()
  })
})

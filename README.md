# @circle-fin/daa-react-native-sdk

React Native SDK for **Digital Asset Accounts (DAA)** — attested authentication
and self-custody DAA API access.

Login is a three-call ceremony — Prepare, Social Session, Device Registration
Complete. Tests can finish the ceremony with `./testing`.

## Features

- `DaaClient` + `DaaSdkConfiguration`, including the closed `keyPolicy`
  (`DEVICE_KEY_POLICY`: hardware-backed, per-signature user verification).
- Injected `DaaTransport` boundary (`DaaHttpRequest` / `DaaHttpResponse`) — the
  SDK never embeds a service credential.
- Deterministic **exact-byte** body serialization (serialize once, sign/send the
  same immutable bytes).
- **Registered-device authorization**: compact ES256 JWS in
  `X-Device-Authorization` (`authorizeExactRequest` / `postSignedResource`).
  Not on the public `.` entry. Tests use the `./testing` in-memory store;
  production `signExactBytes` reaches Expo `signDeviceAuthorization`. Account,
  transfer, and withdrawal `create` are wired through it.
- The DAA **Owner-key** interfaces (P-256 / ES256) on the public entry. No
  generic signing API. The concrete WebCrypto-backed in-memory **test double**
  is exported only from the `./testing` subpath and fails closed in a React
  Native release bundle.
- `DaaSdkError` model.
- Typed reads for accounts, account limits/usage, deposit addresses, deposits,
  transfers, withdrawals, and wire/ACH fiat accounts (plus their receiving
  instructions) behind `DaaUserClient`, plus unsigned deposit-address
  create-or-resolve and the Owner-authorized `accounts.create` /
  `transfers.create` / `withdrawals.create`.
  All three signed creates take their request shape from the Owner-authorization
  registry, reject a property it does not name before anything is signed, and
  fail closed until the AuthKey carries Circle's registration acknowledgement.
  Account, deposit-address, deposit, transfer, and withdrawal listings return
  trusted pages: navigation accepts only same-origin links for the originating
  collection and preserves the API's opaque query exactly.
  `accountLimits.get(accountId, query?)` reads
  `GET /v1/accounts/{accountId}/limits/usage`; the public API reference
  ([list-account-limits-usage](https://developers.circle.com/api-reference/digital-asset-accounts/all/list-account-limits-usage))
  is its contract. `usd_cents` and `count` values are returned
  unconverted:

  ```ts
  const usage = await daaUserClient.accountLimits.get('1000662322', {
    operation: 'withdrawal',
    window: 'P30D',
  })
  for (const item of usage.items) {
    console.log(item.operation.kind, item.effectiveThreshold, item.usagePercent)
  }
  ```

  Response models are exported as **types only**: every instance a caller holds
  came from a response the SDK decoded. Reached through `DaaClient.forUser(context)`,
  which opens only for an `ACTIVE` `DaaUserContext` from Device Registration
  Complete.

- `DaaUserClient.refreshContext()` and `.close()` — the lifecycle methods.
  `refreshContext` is a signed `get_device_context` read
  (`GET /v1/accounts/auth/context`), not an unsigned one: it carries a fresh
  `X-Device-Authorization` over the empty body byte array and decodes the same
  `DeviceContext` shape Device Registration Complete returns. This SDK holds
  no retained context object and no cancellable in-flight work, so `close()`
  refuses all further work through this instance: `refreshContext`,
  every signed `create` on `accounts` / `transfers` / `withdrawals`, every
  unsigned read, the unsigned `depositAddresses.create`, and `next()` /
  `previous()` on a previously returned `Page` fail closed with
  `contract_violation` afterward. A request already sent completes. The
  registered AuthKey itself is untouched.
- `AuthClient.prepareSocialLogin` — the Prepare call. Mints a registration code
  verifier and an ephemeral P-256 registration-flow key, then
  `POST /v1/accounts/auth/loginRequests` with the S256 challenge and the flow
  public key. It touches **no AuthKey**: AuthKey selection comes after the
  Social Session response, so nothing at Prepare reads the secure-key store.
  Returns a `PreparedSocialLogin` (`loginRequestId`, `oidcNonce`, `oidcState`,
  `prepareReceiptJws`, `expiresAt`). No Prepare-receipt trust anchor is pinned
  in this release, so the SDK ignores any receipt the service sends and login
  proceeds as if none arrived (`prepareReceiptJws` is null). `oidcNonce` and
  `oidcState` are therefore not authenticated by the SDK, and the receipt never
  signs `oidcState`: bind the provider redirect with your app's own OAuth
  `state`, and carry `oidcState` inside or next to it. `completeSocialSession` posts
  `POST /v1/accounts/auth/sessions` and selects the AuthKey only after that
  response. It takes the provider `idToken` **and** the `clientEntityId` of an
  end user the application's own backend has already onboarded: the service
  requires that field and Circle never creates the entity, so an application
  onboards first and passes the id here.
  `PendingDeviceRegistration.complete` sends Device Registration
  Complete with `X-Registration-Flow-Authorization` and
  `X-Device-Authorization` over the exact four-field body.

Prepare mints the verifier and flow key through the Expo `DaaRegistration`
module (`DaaSecureRandom` / `DaaRegistrationFlowKey` in the native SDKs), not
through `DaaSecureKey` and not through host WebCrypto. The same module checks
the receipt signature by delegating to the native SDKs'
`DaaPrepareReceiptSignature`. A React Native host missing that module fails
closed with `contract_violation` when minting, and a receipt it cannot verify
for want of the module is `prepare_receipt_invalid`.
Node tests inject a fake in `jest.setup.js`.

The Expo `DaaSecureKey` module (`ios/`, `android/`, `expo-module.config.json`)
delegates Owner AuthKey operations to the native SDKs, and
`resolveNativeBridge()` loads it via `requireOptionalNativeModule` — failing
closed in Node and Jest where no native module exists.
`X-Device-Authorization` is minted in TypeScript (`authorizeExactRequest`);
production `signExactBytes` reaches Expo `signDeviceAuthorization`.

## Installing

```
yarn add @circle-fin/daa-react-native-sdk
```

### The native SDKs are separate artifacts

This package bridges to two native SDKs published as coordinates rather than
vendoring them. The
tarball ships `DaaReactNativeSdk.podspec` and `android/build.gradle`, which only
_declare_ the native dependencies — installing from npm does not fetch them. The
host app's own CocoaPods and Gradle resolve them at build time.

**iOS.** `daa-ios-sdk` is a CocoaPods spec source, not published to the public
trunk. Add it alongside the CDN in your `Podfile`, then `pod install`:

```ruby
source 'https://github.com/circlefin/daa-ios-sdk.git'
source 'https://cdn.cocoapods.org/'
```

**Android.** `com.circle.daa:daa-android-sdk` is published to GitHub Packages,
which needs a GitHub token even for public packages. Add a `maven {}` block to
your app's root `build.gradle`, sourced from the environment so nothing is
committed:

```gradle
allprojects {
    repositories {
        // ...your existing repositories
        maven {
            url System.getenv('DAA_ANDROID_MAVEN_URL')
            credentials {
                username System.getenv('DAA_ANDROID_MAVEN_USERNAME')
                password System.getenv('DAA_ANDROID_MAVEN_PASSWORD')
            }
        }
    }
}
```

| Variable                     | Value                                                    |
| ---------------------------- | -------------------------------------------------------- |
| `DAA_ANDROID_MAVEN_URL`      | `https://maven.pkg.github.com/circlefin/daa-android-sdk` |
| `DAA_ANDROID_MAVEN_USERNAME` | your GitHub username                                     |
| `DAA_ANDROID_MAVEN_PASSWORD` | a GitHub PAT with `read:packages` scope                  |

### Upgrading to `DaaSdk` 0.5.1 and `daa-android-sdk` 0.5.0

- **The biometric prompt text belongs to the native SDKs.** Face ID, Touch ID
  and the Android BiometricPrompt show text that the native SDK sets from the
  operation being signed, for example `Authorizing: transfer`. The text is
  English only. Your app cannot set or change it.
- **iOS apps that share Keychain items may lose their AuthKey.** The AuthKey now
  lives in your app's own application-identifier Keychain group
  (`<App ID prefix>.<bundle identifier>`). Before, it lived in the first group
  of your `keychain-access-groups` entitlement. If you use Keychain Sharing and
  a shared group is first in that list, the SDK does not find the AuthKey that
  an earlier version created. `resolveOrCreate` returns `"created"`, and the
  device must register again. Apps without Keychain Sharing, and apps that list
  their own group first, are not affected.
- **iOS fails closed when the AuthKey Keychain group cannot be resolved.** If
  the SDK cannot resolve your app's own group, for example in a background
  launch before the first unlock after boot, the call throws instead of running
  an unscoped Keychain query. Nothing is cached, so a later call tries again.
- **Android needs an Auth Tab browser for a custom-scheme enrollment
  redirect.** A custom-scheme `redirectUri` for `enroll` now runs only in an
  Auth Tab. On a device with no allowed browser that offers one, `enroll`
  rejects with a `ScaError` whose `code` is `Unsupported` and whose `reason` is
  `InsecureRedirect`, and nothing opens. An `https` App Link is not affected,
  and `approve` already refuses a custom scheme.

## Layout

```
src/
  index.ts               Public surface — `.` (types + client + serialization)
  testing.ts             `./testing` subpath — in-memory secure-key test double
  DaaClient.ts           Root client + configuration
  api/                   AuthClient, DaaUserClient + typed resource clients
  auth/                  Login-attempt material (registration-flow key, verifier, receipt)
  models/                Typed account, page, address, deposit, transfer, withdrawal, fiat-account (wire/ACH), money, and prepared-login models
  wire/                  Response decoding: `data` envelope, payload mapping
  transport/             Injected transport boundary
  crypto/                Exact-byte serialization, Base64URL, SHA-256, JWK thumbprint, native-backed CSPRNG
  securekey/             DAA Owner-key interfaces + in-memory & native-bridge stores
  errors.ts              DaaSdkError model + DaaError
DaaReactNativeSdk.podspec  Declares the DaaSdk CocoaPods dependency
android/build.gradle       Declares the com.circle.daa:daa-android-sdk dependency
ios/                       Expo DaaSecureKey + DaaRegistration Swift modules
android/src/               Expo DaaSecureKey + DaaRegistration Kotlin modules
expo-module.config.json    Expo autolinking
```

## Develop

```bash
yarn install
yarn test         # unit tests (jest + ts-jest)
yarn check:type   # tsc --noEmit
```

## References

- Reporting a security vulnerability: [`SECURITY.md`](./SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](./CONTRIBUTING.md)

## License

[Apache License 2.0](LICENSE)

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

/**
 * Return a standalone `ArrayBuffer` holding a copy of the view's bytes.
 *
 * WebCrypto's `BufferSource` parameters want an `ArrayBuffer`-backed view; under
 * TypeScript's typed-array generics a plain `Uint8Array` may be
 * `Uint8Array<ArrayBufferLike>` (possibly `SharedArrayBuffer`-backed) and does
 * not satisfy that. Copying to a fresh `ArrayBuffer` sidesteps the mismatch and
 * keeps callers passing the exact bytes.
 */
export function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer
}

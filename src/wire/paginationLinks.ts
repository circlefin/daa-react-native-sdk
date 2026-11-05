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

import { contractViolation } from '../errors'
import type { DaaHttpResponse } from '../transport/DaaTransport'

type TrustedTarget = Readonly<{ query: string | null }>

export type TrustedPaginationTargets = Readonly<{
  next: TrustedTarget | null
  previous: TrustedTarget | null
}>

type LinkValue = Readonly<{
  target: string
  relation: string
}>

// RFC 3986 query = *( pchar / "/" / "?" ). Percent escapes are checked
// separately so the opaque substring can be forwarded without normalizing it.
const RAW_QUERY_CHARACTERS = /^[A-Za-z0-9._~!$&'()*+,;=:@/?%-]*$/

/** Parse and trust-check navigation metadata from an untrusted API response. */
export function trustedPaginationTargets(
  response: DaaHttpResponse,
  publicApiOrigin: string,
  expectedPath: string,
): TrustedPaginationTargets {
  const matchingHeaders = Object.keys(response.headers).filter(
    (name) => name.toLowerCase() === 'link',
  )
  if (matchingHeaders.length === 0) {
    return { next: null, previous: null }
  }
  if (matchingHeaders.length !== 1) {
    throw contractViolation('the response contains ambiguous pagination metadata')
  }

  const header = response.headers[matchingHeaders[0] as string]
  if (header === undefined) {
    throw contractViolation('the response contains malformed pagination metadata')
  }

  let nextTarget: string | null = null
  let previousTarget: string | null = null
  for (const link of parseLinkHeader(header)) {
    if (link.relation === 'next') {
      if (nextTarget !== null) {
        throw contractViolation('the response contains ambiguous pagination metadata')
      }
      nextTarget = link.target
    } else if (link.relation === 'prev') {
      if (previousTarget !== null) {
        throw contractViolation('the response contains ambiguous pagination metadata')
      }
      previousTarget = link.target
    }
  }

  return {
    next: nextTarget === null ? null : trustedTarget(nextTarget, publicApiOrigin, expectedPath),
    previous:
      previousTarget === null ? null : trustedTarget(previousTarget, publicApiOrigin, expectedPath),
  }
}

/** Accept only DAA's `<target>; rel="value"` shape, plus HTTP comma folding. */
function parseLinkHeader(value: string): readonly LinkValue[] {
  if (value.length === 0 || /[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)) {
    throw contractViolation('the response contains malformed pagination metadata')
  }

  const links: LinkValue[] = []
  let position = 0
  while (position < value.length) {
    position = skipOptionalWhitespace(value, position)
    if (value[position] !== '<') {
      throw contractViolation('the response contains malformed pagination metadata')
    }
    const targetEnd = value.indexOf('>', position + 1)
    if (targetEnd < 0) {
      throw contractViolation('the response contains malformed pagination metadata')
    }
    const target = value.slice(position + 1, targetEnd)
    position = skipOptionalWhitespace(value, targetEnd + 1)
    if (value[position] !== ';') {
      throw contractViolation('the response contains malformed pagination metadata')
    }

    position = skipOptionalWhitespace(value, position + 1)
    const relationMatch = /^rel="([!#$%&'*+.^_`|~0-9A-Za-z-]+)"/i.exec(value.slice(position))
    if (relationMatch === null) {
      throw contractViolation('the response contains malformed pagination metadata')
    }
    const relation = (relationMatch[1] as string).toLowerCase()
    position += relationMatch[0].length
    position = skipOptionalWhitespace(value, position)

    links.push({ target, relation })
    if (position === value.length) {
      break
    }
    if (value[position] !== ',') {
      throw contractViolation('the response contains malformed pagination metadata')
    }
    position = skipOptionalWhitespace(value, position + 1)
    if (position >= value.length) {
      throw contractViolation('the response contains malformed pagination metadata')
    }
  }
  return Object.freeze(links)
}

function skipOptionalWhitespace(value: string, start: number): number {
  let position = start
  while (value[position] === ' ' || value[position] === '\t') position += 1
  return position
}

function trustedTarget(
  target: string,
  publicApiOrigin: string,
  expectedPath: string,
): TrustedTarget {
  if (
    target.length === 0 ||
    target !== target.trim() ||
    /[\u0000-\u001f\u007f\\]/.test(target) ||
    /%(?![0-9A-Fa-f]{2})/.test(target)
  ) {
    throw contractViolation('the response contains an untrusted pagination link')
  }

  const raw = /^https:\/\/([^/?#]+)(\/[^?#]*)?(\?[^#]*)?$/i.exec(target)
  if (raw === null) {
    throw contractViolation('the response contains an untrusted pagination link')
  }

  const targetOrigin = canonicalHttpsOrigin(raw[1] as string)
  const trustedOrigin = canonicalTrustedOrigin(publicApiOrigin)
  if (targetOrigin === null || trustedOrigin === null || targetOrigin !== trustedOrigin) {
    throw contractViolation('the response contains an untrusted pagination link')
  }

  const rawPath = raw[2] ?? '/'
  if (
    rawPath !== expectedPath ||
    !rawPath.startsWith('/v1/') ||
    rawPath.includes('%') ||
    rawPath.includes('//')
  ) {
    throw contractViolation('the response contains an untrusted pagination link')
  }

  const rawQuery = raw[3]
  const query = rawQuery === undefined ? null : rawQuery.slice(1)
  if (query !== null && !RAW_QUERY_CHARACTERS.test(query)) {
    throw contractViolation('the response contains an untrusted pagination link')
  }
  return Object.freeze({ query })
}

/**
 * Canonicalize only the HTTPS authority accepted by the pagination grammar.
 *
 * URL parsing is deliberately not used here: React Native hosts do not all
 * expose the same WHATWG URL implementation as Node. The raw target/path
 * checks above already reject URL syntax we do not forward, so the trust
 * decision only needs a small deterministic host/port canonicalizer.
 */
function canonicalHttpsOrigin(authority: string): string | null {
  if (authority.includes('@') || authority.includes('%')) return null
  const match = /^([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$/.exec(authority)
  if (match === null) return null
  const host = match[1] as string
  const rawPort = match[2]
  if (rawPort !== undefined) {
    const port = Number(rawPort)
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null
    if (port === 443) return `https://${host.toLowerCase()}`
    return `https://${host.toLowerCase()}:${port}`
  }
  return `https://${host.toLowerCase()}`
}

function canonicalTrustedOrigin(origin: string): string | null {
  const match = /^https:\/\/([^/?#]+)$/i.exec(origin)
  return match === null ? null : canonicalHttpsOrigin(match[1] as string)
}

import type { Environment } from '../types';

/**
 * DoH endpoint for the MX check. Cloudflare's resolver needs no key and the
 * `accept: application/dns-json` header the Workers runtime sends. A test can
 * stub the global `fetch` to answer the DoH endpoint without touching this
 * constant.
 */
const DOH_URL = 'https://cloudflare-dns.com/dns-query';

/** A DNS-over-HTTPS response (RFC 8484 JSON). */
interface DohResponse {
    Status: number;
    Answer?: { type: number }[];
}

/** The lookup a test can substitute for the real network call. */
export type MxLookup = (domain: string) => Promise<boolean | null>;

/** True when the value explicitly disables the MX check. */
function isExplicitlyOff(value: string | undefined): boolean {
    const norm = (value ?? '').trim().toLowerCase();
    return norm === 'false' || norm === '0';
}

/** The domain after the `@`, lower-cased. Empty when the address has none. */
export function senderDomain(address: string | null | undefined): string {
    if (!address) {
        return '';
    }
    const at = address.lastIndexOf('@');
    if (at === -1) {
        return '';
    }
    return address.slice(at + 1).trim().toLowerCase();
}

/**
 * Tri-state verdict for one DoH MX query. The result is what the handler will
 * act on, so the three cases must stay distinct:
 *
 * - `true`  — NOERROR with at least one type-15 (MX) record: the domain takes mail.
 * - `false` — an authoritative "no": NXDOMAIN (the domain does not exist) or
 *             NOERROR with no MX record (it exists but accepts no mail).
 * - `null`  — no usable answer: SERVFAIL or any other transient RCODE. The
 *             domain may well have an MX; the resolver just could not say so.
 *
 * A type-1 record only (the domain has an A record) is not an MX record, so it
 * still resolves to `false` under NOERROR.
 */
export function interpretDohMx(response: DohResponse): boolean | null {
    if (response.Status === 3) {
        return false;
    }
    if (response.Status === 0) {
        return (response.Answer ?? []).some(record => record.type === 15);
    }
    return null;
}

/**
 * Default lookup: one DoH MX query for `domain`. A transport error or a failed
 * HTTP response returns `null` ("no answer") rather than `false`, so a resolver
 * outage cannot be mistaken for a domain that has no MX record.
 */
export const lookupMx: MxLookup = async (domain: string): Promise<boolean | null> => {
    try {
        const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(domain)}&type=MX`, {
            headers: { accept: 'application/dns-json' },
        });
        if (!res.ok) {
            return null;
        }
        return interpretDohMx((await res.json()) as DohResponse);
    } catch {
        return null;
    }
};

/**
 * Whether the sender domain is rejected by the MX check.
 *
 * The check is on by default; only an explicit `MX_CHECK=false` or `0` turns it
 * off. When on, a sender with no domain (a missing or malformed address) is
 * skipped rather than rejected: a domainless envelope sender is a transport
 * artefact, not a spoofing signal, and rejecting it would lose mail the address
 * lists let through. A domain is blocked only on an authoritative "no MX"; a
 * `null` verdict (resolver outage) fails open and lets the mail through.
 */
export async function isSenderMxBlocked(address: string | null | undefined, env: Environment): Promise<boolean> {
    if (isExplicitlyOff(env.MX_CHECK)) {
        return false;
    }
    const domain = senderDomain(address);
    if (!domain) {
        return false;
    }
    return (await lookupMx(domain)) === false;
}

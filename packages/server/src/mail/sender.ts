import type { EmailMessage, ForwardableEmailMessage } from '@cloudflare/workers-types';
import type { Environment } from '../types';
import { headerAddress } from './check';
import { senderDomain } from './mx';

/** True when the value explicitly disables the sender-match check. */
function isExplicitlyOff(value: string | undefined): boolean {
    const norm = (value ?? '').trim().toLowerCase();
    return norm === 'false' || norm === '0';
}

/**
 * Whether a delivery is a self-spoofing message.
 *
 * A self-spoof is one where the `From` header claims to be the recipient's own
 * domain while the mail actually arrived from a different domain's envelope.
 * That is the shape of the "your account logged in from a new device" phishing
 * that lands in the owner's own mailbox: the attacker points `From` at the
 * victim's domain so the alert reads as an internal notice, but the SMTP
 * envelope (the `message.from` MAIL FROM) is the attacker's real domain. A relay
 * authenticates only the envelope, so the forged `From` passes unchallenged.
 *
 * The check is deliberately narrower than "envelope domain differs from the
 * From domain". A plain mismatch is not a spoof: provider mail (SES and the
 * like) carries a bounce address in the envelope that differs from the `From`
 * header by design, and that must keep arriving. First-party mail from the same
 * domain also keeps its envelope and `From` in the one domain, so no mismatch
 * exists. Only the "from yourself" pattern — `From` domain equals the recipient
 * domain but the envelope came from somewhere else — is a spoofing signal, and
 * that is what gets rejected.
 *
 * The check is on by default; only an explicit `SENDER_MATCH_CHECK=false` or `0`
 * turns it off. A message missing any of the three addresses (no `From` header,
 * no envelope sender, no recipient) is skipped rather than rejected, because a
 * domainless field is a transport artefact, not a spoof.
 */
export function isSenderMismatchBlocked(message: EmailMessage, env: Environment): boolean {
    if (isExplicitlyOff(env.SENDER_MATCH_CHECK)) {
        return false;
    }
    // Only `ForwardableEmailMessage` carries the headers; read defensively.
    const headers = (message as Partial<ForwardableEmailMessage>).headers;
    const fromDomain = senderDomain(headerAddress(headers?.get('From')));
    const toDomain = senderDomain(message.to);
    const envelopeDomain = senderDomain(message.from);
    if (!fromDomain || !toDomain || !envelopeDomain) {
        return false;
    }
    // The `From` header must claim to be the recipient's own domain for this to
    // be a self-spoof; a different From domain is ordinary third-party mail.
    if (fromDomain !== toDomain) {
        return false;
    }
    // The mail actually arrived from a different domain.
    return envelopeDomain !== fromDomain;
}

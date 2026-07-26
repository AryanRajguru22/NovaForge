import { authenticator } from "otplib";

// otplib's built-in `window` option only extends tolerance in whole 30-second
// steps (window: 1 = +/-30s) -- there's no way to ask it for a tighter,
// sub-step tolerance while keeping step: 30, which we must keep since every
// real authenticator app (Google Authenticator, Authy, etc.) hardcodes a
// 30-second step per RFC 6238 and would be enrolled against a QR code
// generated with that same step. The library's actual default (window: 0,
// left unset anywhere in this codebase) gives *zero* tolerance: a code is
// only accepted for the exact current 30-second bucket, so a client clock
// that's merely a few seconds ahead or behind at the moment someone finishes
// typing a code can get rejected for no real reason.
//
// Since a TOTP code is just HMAC(secret, floor(epoch / step)), and that
// counter only changes at step boundaries, sampling the code at the two
// endpoints of a +/-toleranceMs window (as well as "now") accepts a code iff
// the window genuinely overlaps the 30-second bucket that produced it -- the
// correct semantics given the wire format is fundamentally bucketed at the
// step size, not individual seconds.
//
// One inherent consequence worth naming: because buckets are 30s wide but
// the tolerance is only 5s, a code can occasionally be accepted from a drift
// a little past 5s if the server's clock happens to sit close enough to a
// bucket boundary (a 4s-behind client and an 8s-behind client can land in
// the identical bucket and produce byte-for-byte the same code -- the server
// has no way to tell them apart). This is unavoidable at any tolerance
// smaller than the step size, not a bug: the only thing that IS guaranteed
// precisely is the reject side once drift exceeds step + tolerance (here,
// 35s), since at that distance the two windows can never share a bucket
// regardless of boundary phase.
const CLOCK_TOLERANCE_MS = 5_000;

export function checkTotpWithTolerance(
  token: string,
  secret: string,
  toleranceMs: number = CLOCK_TOLERANCE_MS,
  now: number = Date.now(),
): boolean {
  return [0, -toleranceMs, toleranceMs].some((offsetMs) =>
    authenticator.clone({ epoch: now + offsetMs }).check(token, secret),
  );
}

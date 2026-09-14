interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

const TTL_MS = 5 * 60 * 1000;
const store = new Map<string, ChallengeEntry>();
let lastSweep = 0;

// Entries that are never claimed (an abandoned ceremony) would otherwise stay
// in memory forever; drop expired ones at most once a minute.
function sweepExpired(now: number): void {
  if (now - lastSweep < 60_000) return;
  lastSweep = now;
  for (const [key, entry] of store) {
    if (entry.expiresAt < now) store.delete(key);
  }
}

export function setChallenge(key: string, challenge: string): void {
  const now = Date.now();
  sweepExpired(now);
  store.set(key, { challenge, expiresAt: now + TTL_MS });
}

/** Reads and immediately deletes the challenge — WebAuthn challenges are single-use. */
export function takeChallenge(key: string): string | undefined {
  const entry = store.get(key);
  store.delete(key);
  if (!entry || entry.expiresAt < Date.now()) return undefined;
  return entry.challenge;
}

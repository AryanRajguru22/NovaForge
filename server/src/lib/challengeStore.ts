interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

const TTL_MS = 5 * 60 * 1000;
const store = new Map<string, ChallengeEntry>();

export function setChallenge(key: string, challenge: string): void {
  store.set(key, { challenge, expiresAt: Date.now() + TTL_MS });
}

/** Reads and immediately deletes the challenge — WebAuthn challenges are single-use. */
export function takeChallenge(key: string): string | undefined {
  const entry = store.get(key);
  store.delete(key);
  if (!entry || entry.expiresAt < Date.now()) return undefined;
  return entry.challenge;
}

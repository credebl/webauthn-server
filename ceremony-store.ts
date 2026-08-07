import { randomUUID } from "crypto";

export type CeremonyType = "registration" | "authentication";

export type PendingCeremony = {
  challenge: string;
  expiresAt: number;
  type: CeremonyType;
  userId: string;
};

/**
 * Holds short-lived WebAuthn ceremony state. A production deployment must replace this with a
 * shared, durable store when it runs more than one process.
 */
export class CeremonyStore {
  private readonly pending = new Map<string, PendingCeremony>();

  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  create(type: CeremonyType, userId: string, challenge: string): string {
    this.removeExpired();
    const ceremonyId = randomUUID();
    this.pending.set(ceremonyId, {
      challenge,
      expiresAt: this.now() + this.ttlMs,
      type,
      userId,
    });
    return ceremonyId;
  }

  /** Returns and removes valid state so a ceremony cannot be replayed. */
  consume(ceremonyId: string, type: CeremonyType): PendingCeremony | undefined {
    const ceremony = this.pending.get(ceremonyId);
    this.pending.delete(ceremonyId);

    if (!ceremony || ceremony.type !== type || ceremony.expiresAt <= this.now()) {
      return undefined;
    }

    return ceremony;
  }

  private removeExpired(): void {
    for (const [ceremonyId, ceremony] of this.pending) {
      if (ceremony.expiresAt <= this.now()) {
        this.pending.delete(ceremonyId);
      }
    }
  }
}

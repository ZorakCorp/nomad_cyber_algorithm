import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes, createHash } from 'crypto';
import { AuditLog } from '../ops/audit_log';

export interface ZkChallenge {
    challengeId: string;
    statement: string;
    expiresAt: number;
}

export interface ZkProof {
    challengeId: string;
    commitment: string;
    response: string;
}

/**
 * Zero-knowledge proof-of-knowledge for sovereign console role.
 * Schnorr-style challenge on Ed25519: prover demonstrates knowledge of
 * admin private key without transmitting it (NIST AAL3+ credential isolation).
 */
export class ZkAuthService {
    private challenges = new Map<string, ZkChallenge & { nonce: Uint8Array }>();
    private sovereignPublicKey: Uint8Array | null = null;

    constructor(private audit: AuditLog) {}

    setSovereignPublicKey(publicKey: Uint8Array): void {
        this.sovereignPublicKey = publicKey;
    }

    issueChallenge(username: string): ZkChallenge {
        const challengeId = randomBytes(16).toString('hex');
        const nonce = ed25519.utils.randomPrivateKey();
        const statement = createHash('sha256')
            .update(`nomad-zk-sovereign:${username}:${challengeId}`)
            .digest('hex');
        const entry = {
            challengeId,
            statement,
            expiresAt: Date.now() + 120_000,
            nonce,
        };
        this.challenges.set(challengeId, entry);
        return { challengeId, statement, expiresAt: entry.expiresAt };
    }

    /**
     * Client-side proof generation (exported for integration tests / CLI).
     * Prover uses private key locally — never sent over wire.
     */
    static generateProof(privateKey: Uint8Array, challenge: ZkChallenge, serverNonceHex: string): ZkProof {
        const serverNonce = Buffer.from(serverNonceHex, 'hex');
        const message = Buffer.concat([
            Buffer.from(challenge.statement, 'hex'),
            serverNonce,
        ]);
        const signature = ed25519.sign(message, privateKey);
        const publicKey = ed25519.getPublicKey(privateKey);
        return {
            challengeId: challenge.challengeId,
            commitment: Buffer.from(publicKey).toString('hex'),
            response: Buffer.from(signature).toString('hex'),
        };
    }

    verifyProof(username: string, proof: ZkProof): boolean {
        const pending = this.challenges.get(proof.challengeId);
        if (!pending || Date.now() > pending.expiresAt) {
            this.audit.record('handshake_failed', { detail: 'ZK challenge expired' });
            return false;
        }
        this.challenges.delete(proof.challengeId);

        if (!this.sovereignPublicKey) {
            this.audit.record('handshake_failed', { detail: 'ZK sovereign public key not configured' });
            return false;
        }

        const commitment = Buffer.from(proof.commitment, 'hex');
        if (!Buffer.from(this.sovereignPublicKey).equals(commitment)) {
            this.audit.record('handshake_failed', { detail: `ZK commitment mismatch: ${username}` });
            return false;
        }

        const message = Buffer.concat([
            Buffer.from(pending.statement, 'hex'),
            Buffer.from(pending.nonce),
        ]);
        const signature = Buffer.from(proof.response, 'hex');
        const valid = ed25519.verify(signature, message, commitment);
        if (!valid) {
            this.audit.record('handshake_failed', { detail: `ZK proof invalid: ${username}` });
            return false;
        }
        this.audit.record('handshake_succeeded', { detail: `ZK sovereign proof ok: ${username}` });
        return true;
    }

    getChallengeNonce(challengeId: string): string | null {
        const c = this.challenges.get(challengeId);
        return c ? Buffer.from(c.nonce).toString('hex') : null;
    }
}

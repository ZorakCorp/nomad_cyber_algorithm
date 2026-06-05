import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import { randomBytes } from 'crypto';
import { AuditLog } from '../ops/audit_log';

export interface WebAuthnCredential {
    credentialId: string;
    publicKey: Uint8Array;
    counter: number;
    transports?: AuthenticatorTransport[];
}

export interface WebAuthnChallenge {
    challenge: string;
    expiresAt: number;
}

const RP_NAME = 'Nomad Sovereign Console';
const RP_ID = process.env.NOMAD_WEBAUTHN_RP_ID ?? 'localhost';
const ORIGIN = process.env.NOMAD_WEBAUTHN_ORIGIN ?? `http://${RP_ID}:8081`;

export class WebAuthnAuthService {
    private credentials = new Map<string, WebAuthnCredential>();
    private pendingChallenges = new Map<string, WebAuthnChallenge>();

    constructor(private audit: AuditLog) {}

    registerCredential(username: string, credentialId: string, publicKey: Uint8Array): void {
        this.credentials.set(`${username}:${credentialId}`, {
            credentialId,
            publicKey,
            counter: 0,
        });
    }

    async beginAuthentication(username: string): Promise<{ options: Awaited<ReturnType<typeof generateAuthenticationOptions>>; sessionId: string }> {
        const userCreds = [...this.credentials.entries()]
            .filter(([k]) => k.startsWith(`${username}:`))
            .map(([, v]) => v);

        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: userCreds.map((c) => ({
                id: c.credentialId,
                transports: c.transports,
            })),
            userVerification: 'required',
        });

        const sessionId = randomBytes(16).toString('hex');
        this.pendingChallenges.set(sessionId, {
            challenge: options.challenge,
            expiresAt: Date.now() + 120_000,
        });
        return { options, sessionId };
    }

    async verifyAuthentication(
        username: string,
        sessionId: string,
        response: Parameters<typeof verifyAuthenticationResponse>[0]['response']
    ): Promise<boolean> {
        const pending = this.pendingChallenges.get(sessionId);
        if (!pending || Date.now() > pending.expiresAt) {
            this.audit.record('handshake_failed', { detail: 'WebAuthn challenge expired' });
            return false;
        }
        this.pendingChallenges.delete(sessionId);

        const credId = Buffer.from(response.id, 'base64url').toString('base64url');
        const stored = this.credentials.get(`${username}:${credId}`);
        if (!stored) {
            this.audit.record('handshake_failed', { detail: `WebAuthn credential not found: ${username}` });
            return false;
        }

        let verification: VerifiedAuthenticationResponse;
        try {
            verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge: pending.challenge,
                expectedOrigin: ORIGIN,
                expectedRPID: RP_ID,
                credential: {
                    id: stored.credentialId,
                    publicKey: Buffer.from(stored.publicKey),
                    counter: stored.counter,
                },
                requireUserVerification: true,
            });
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            this.audit.record('handshake_failed', { detail: `WebAuthn verification failed: ${msg}` });
            return false;
        }

        if (!verification.verified) {
            this.audit.record('handshake_failed', { detail: `WebAuthn assertion invalid: ${username}` });
            return false;
        }

        stored.counter = verification.authenticationInfo.newCounter;
        this.audit.record('handshake_succeeded', { detail: `WebAuthn MFA ok: ${username}` });
        return true;
    }

    hasCredentials(username: string): boolean {
        return [...this.credentials.keys()].some((k) => k.startsWith(`${username}:`));
    }
}

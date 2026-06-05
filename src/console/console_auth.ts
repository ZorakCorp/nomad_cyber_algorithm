import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import * as argon2 from 'argon2';
import { NomadConfig } from '../config';
import { AuditLog } from '../ops/audit_log';
import { Principal } from '../gateway/rbac';
import { StructuredLogger } from '../ops/logger';
import { WebAuthnAuthService } from './webauthn_auth';
import { ZkAuthService } from './zk_auth';
import { VitalGuard } from '../organism/vital_guard';

export interface ConsoleUser {
    username: string;
    passwordHash: string;
    passwordSalt: string;
    totpSecret: string;
    roles: Array<'viewer' | 'operator' | 'admin' | 'sovereign'>;
    webauthnCredentialId?: string;
    webauthnPublicKey?: Uint8Array;
}

export interface ConsoleSession {
    token: string;
    username: string;
    roles: ConsoleUser['roles'];
    mfaVerified: boolean;
    webauthnVerified: boolean;
    zkVerified: boolean;
    expiresAt: number;
}

const ARGON2_OPTIONS: argon2.Options & { raw?: false } = {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
};

const FORBIDDEN_PASSWORD_SUBSTRINGS = [
    'change', 'password', 'admin', 'default', 'secret', 'nomad',
];

const DUMMY_SALT = Buffer.from('6e6f6d61642d64756d6d792d73616c742d3031', 'hex');
const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$dummy$invalidhashvalue000000000000000000';

async function hashPassword(password: string, salt: Buffer): Promise<string> {
    return argon2.hash(password, { ...ARGON2_OPTIONS, salt });
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
        return await argon2.verify(hash, password);
    } catch {
        return false;
    }
}

function counterToBuffer(counter: number): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter));
    return buf;
}

/** RFC 6238 TOTP — dev fallback only; production requires WebAuthn (NIST AAL3). */
export function generateTotp(secret: string, timestampMs = Date.now()): string {
    const counter = Math.floor(timestampMs / 30_000);
    const hmac = createHmac('sha1', Buffer.from(secret, 'utf8'))
        .update(counterToBuffer(counter))
        .digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = ((hmac[offset] & 0x7f) << 24 |
        (hmac[offset + 1] & 0xff) << 16 |
        (hmac[offset + 2] & 0xff) << 8 |
        (hmac[offset + 3] & 0xff)) % 1_000_000;
    return code.toString().padStart(6, '0');
}

function verifyTotp(secret: string, code: string, timestampMs = Date.now()): boolean {
    const normalized = code.padStart(6, '0');
    for (const offset of [-1, 0, 1]) {
        const expected = generateTotp(secret, timestampMs + offset * 30_000);
        const a = Buffer.from(normalized);
        const b = Buffer.from(expected);
        if (a.length === b.length && timingSafeEqual(a, b)) return true;
    }
    return false;
}

function containsForbiddenSubstring(value: string): string | null {
    const lower = value.toLowerCase();
    for (const word of FORBIDDEN_PASSWORD_SUBSTRINGS) {
        if (lower.includes(word)) return word;
    }
    return null;
}

export function validateStartupSecretsOrThrow(devMode = process.env.NOMAD_DEV_MODE === 'true'): { password: string; totp: string } {
    const password = process.env.NOMAD_CONSOLE_ADMIN_PASSWORD?.trim();
    const totp = process.env.NOMAD_CONSOLE_ADMIN_TOTP?.trim();
    const webauthnRequired = process.env.NOMAD_WEBAUTHN_REQUIRED !== 'false' && !devMode;

    if (!password) {
        throw new Error('NOMAD_CONSOLE_ADMIN_PASSWORD is required. No default credentials are permitted.');
    }
    if (!webauthnRequired && !totp) {
        throw new Error('NOMAD_CONSOLE_ADMIN_TOTP is required when WebAuthn is not enforced.');
    }
    if (password.length < 20) {
        throw new Error(`NOMAD_CONSOLE_ADMIN_PASSWORD must be at least 20 characters (got ${password.length}).`);
    }
    if (totp && totp.length < 16) {
        throw new Error(`NOMAD_CONSOLE_ADMIN_TOTP must be at least 16 characters (got ${totp.length}).`);
    }
    const forbidden = containsForbiddenSubstring(password);
    if (forbidden) {
        throw new Error(`NOMAD_CONSOLE_ADMIN_PASSWORD contains forbidden substring "${forbidden}".`);
    }
    if (devMode && totp) {
        console.warn(JSON.stringify({
            ts: new Date().toISOString(),
            level: 'warn',
            message: 'TOTP MFA active in dev mode — production requires FIDO2/WebAuthn (NIST AAL3).',
            component: 'console_auth',
        }));
    }
    return { password, totp: totp ?? '' };
}

export function validateStartupSecrets(audit?: AuditLog, logger?: StructuredLogger): { password: string; totp: string } {
    try {
        return validateStartupSecretsOrThrow();
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const payload = { level: 'fatal' as const, message, component: 'console_auth' };
        if (logger) {
            logger.error(message, payload);
        } else {
            console.error(JSON.stringify({ ts: new Date().toISOString(), ...payload }));
        }
        audit?.record('handshake_failed', { detail: `FATAL_STARTUP: ${message}` });
        process.exit(1);
    }
}

export class ConsoleAuthService {
    private users = new Map<string, ConsoleUser>();
    private sessions = new Map<string, ConsoleSession>();
    private mfaAttempts = new Map<string, { count: number; resetAt: number }>();
    readonly webauthn: WebAuthnAuthService;
    readonly zk: ZkAuthService;
    private vitalGuard?: VitalGuard;

    private constructor(
        private config: NomadConfig,
        private audit: AuditLog
    ) {
        this.webauthn = new WebAuthnAuthService(audit);
        this.zk = new ZkAuthService(audit);
    }

    static async create(config: NomadConfig, audit: AuditLog, vitalGuard?: VitalGuard): Promise<ConsoleAuthService> {
        const svc = new ConsoleAuthService(config, audit);
        svc.vitalGuard = vitalGuard;
        await svc.initializeAdmin();
        return svc;
    }

    setVitalGuard(guard: VitalGuard): void {
        this.vitalGuard = guard;
    }

    private async initializeAdmin(): Promise<void> {
        const { password, totp } = validateStartupSecrets(this.audit);
        const adminSalt = randomBytes(32);
        const passwordHash = await hashPassword(password, adminSalt);
        this.users.set('admin', {
            username: 'admin',
            passwordSalt: adminSalt.toString('hex'),
            passwordHash,
            totpSecret: totp,
            roles: ['sovereign'],
        });

        const credId = process.env.NOMAD_WEBAUTHN_CREDENTIAL_ID?.trim();
        const credPub = process.env.NOMAD_WEBAUTHN_PUBLIC_KEY?.trim();
        if (credId && credPub) {
            const publicKey = Buffer.from(credPub, 'base64url');
            this.webauthn.registerCredential('admin', credId, publicKey);
        } else if (this.config.webauthnRequired) {
            console.warn(JSON.stringify({
                ts: new Date().toISOString(),
                level: 'warn',
                message: 'NOMAD_WEBAUTHN_CREDENTIAL_ID/PUBLIC_KEY not set — register hardware key before production login.',
                component: 'console_auth',
            }));
        }

        const zkPub = process.env.NOMAD_ZK_SOVEREIGN_PUBLIC_KEY?.trim();
        if (zkPub) {
            this.zk.setSovereignPublicKey(Buffer.from(zkPub, 'hex'));
        }
    }

    async login(username: string, password: string): Promise<{ sessionToken: string; mfaRequired: boolean } | null> {
        try {
            this.vitalGuard?.requireVital('console.login');
        } catch {
            this.audit.record('handshake_failed', { detail: 'console login blocked — organism lockdown' });
            return null;
        }
        const user = this.users.get(username);
        const valid = user ? await verifyPassword(password, user.passwordHash) : await verifyPassword(password, DUMMY_HASH);
        if (!user || !valid) {
            this.audit.record('handshake_failed', { detail: 'console login failed' });
            return null;
        }
        const token = randomBytes(24).toString('hex');
        const session: ConsoleSession = {
            token,
            username,
            roles: user.roles,
            mfaVerified: !this.config.consoleMfaRequired,
            webauthnVerified: !this.config.webauthnRequired,
            zkVerified: user.roles.includes('sovereign') ? false : true,
            expiresAt: Date.now() + this.config.consoleSessionTtlMs,
        };
        this.sessions.set(token, session);
        this.audit.record('handshake_started', { detail: `console login: ${username}` });
        return { sessionToken: token, mfaRequired: this.config.consoleMfaRequired };
    }

    verifyMfa(sessionToken: string, code: string): boolean {
        if (this.config.webauthnRequired) {
            this.audit.record('handshake_failed', { detail: 'TOTP rejected — WebAuthn required in production' });
            return false;
        }
        const session = this.sessions.get(sessionToken);
        if (!session) return false;

        const attempts = this.mfaAttempts.get(sessionToken) ?? { count: 0, resetAt: Date.now() + 300_000 };
        if (Date.now() > attempts.resetAt) {
            attempts.count = 0;
            attempts.resetAt = Date.now() + 300_000;
        }
        if (attempts.count >= 5) {
            this.audit.record('handshake_failed', { detail: 'console MFA rate limited' });
            return false;
        }
        attempts.count++;
        this.mfaAttempts.set(sessionToken, attempts);

        const user = this.users.get(session.username);
        if (!user) return false;
        if (!verifyTotp(user.totpSecret, code)) {
            this.audit.record('handshake_failed', { detail: `console MFA failed: ${session.username}` });
            return false;
        }
        session.mfaVerified = true;
        this.mfaAttempts.delete(sessionToken);
        this.audit.record('handshake_succeeded', { detail: `console TOTP MFA ok: ${session.username}` });
        return true;
    }

    async beginWebAuthn(username: string): Promise<{ options: unknown; sessionId: string } | null> {
        const user = this.users.get(username);
        if (!user) return null;
        return this.webauthn.beginAuthentication(username);
    }

    async verifyWebAuthn(sessionToken: string, sessionId: string, response: Parameters<typeof import('@simplewebauthn/server').verifyAuthenticationResponse>[0]['response']): Promise<boolean> {
        const session = this.sessions.get(sessionToken);
        if (!session) return false;
        const ok = await this.webauthn.verifyAuthentication(session.username, sessionId, response);
        if (ok) {
            session.webauthnVerified = true;
            session.mfaVerified = true;
        }
        return ok;
    }

    issueZkChallenge(username: string): ReturnType<ZkAuthService['issueChallenge']> | null {
        const user = this.users.get(username);
        if (!user || !user.roles.includes('sovereign')) return null;
        return this.zk.issueChallenge(username);
    }

    verifyZkProof(sessionToken: string, proof: Parameters<ZkAuthService['verifyProof']>[1]): boolean {
        const session = this.sessions.get(sessionToken);
        if (!session) return false;
        const ok = this.zk.verifyProof(session.username, proof);
        if (ok) session.zkVerified = true;
        return ok;
    }

    resolveSession(token: string): ConsoleSession | null {
        if (this.vitalGuard && !this.vitalGuard.isVital()) return null;
        const session = this.sessions.get(token);
        if (!session) return null;
        if (Date.now() > session.expiresAt) {
            this.sessions.delete(token);
            return null;
        }
        if (this.config.consoleMfaRequired && !session.mfaVerified) return null;
        if (this.config.webauthnRequired && !session.webauthnVerified) return null;
        const zkRequired = !!process.env.NOMAD_ZK_SOVEREIGN_PUBLIC_KEY?.trim();
        if (zkRequired && session.roles.includes('sovereign') && !session.zkVerified) return null;
        return session;
    }

    toPrincipal(session: ConsoleSession): Principal {
        return { subject: session.username, roles: session.roles };
    }

    resolvePrincipal(token: string): Principal | null {
        const session = this.resolveSession(token);
        return session ? this.toPrincipal(session) : null;
    }
}

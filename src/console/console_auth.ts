import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { NomadConfig } from '../config';
import { AuditLog } from '../ops/audit_log';
import { Principal } from '../gateway/rbac';

export interface ConsoleUser {
    username: string;
    passwordHash: string;
    totpSecret: string;
    roles: Array<'viewer' | 'operator' | 'admin' | 'sovereign'>;
}

export interface ConsoleSession {
    token: string;
    username: string;
    roles: ConsoleUser['roles'];
    mfaVerified: boolean;
    expiresAt: number;
}

const DUMMY_HASH = scryptSync('invalid-login-path', randomBytes(16), 32).toString('hex');

function hashPassword(password: string, salt: Buffer): string {
    return scryptSync(password, salt, 32).toString('hex');
}

function counterToBuffer(counter: number): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter));
    return buf;
}

/** RFC 6238 TOTP with 8-byte big-endian counter. */
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

export class ConsoleAuthService {
    private users = new Map<string, ConsoleUser>();
    private sessions = new Map<string, ConsoleSession>();
    private passwordSalt = randomBytes(16);
    private mfaAttempts = new Map<string, { count: number; resetAt: number }>();

    constructor(
        private config: NomadConfig,
        private audit: AuditLog
    ) {
        const adminSecret = process.env.NOMAD_CONSOLE_ADMIN_TOTP ?? 'NOMAD-DEV-TOTP-SECRET';
        const adminPass = process.env.NOMAD_CONSOLE_ADMIN_PASSWORD ?? 'change-me-in-production';

        if (!config.devMode) {
            if (adminPass === 'change-me-in-production') {
                throw new Error('Set NOMAD_CONSOLE_ADMIN_PASSWORD in production (dev mode is off).');
            }
            if (adminSecret === 'NOMAD-DEV-TOTP-SECRET') {
                throw new Error('Set NOMAD_CONSOLE_ADMIN_TOTP in production (dev mode is off).');
            }
        }

        this.users.set('admin', {
            username: 'admin',
            passwordHash: hashPassword(adminPass, this.passwordSalt),
            totpSecret: adminSecret,
            roles: ['sovereign'],
        });
    }

    login(username: string, password: string): { sessionToken: string; mfaRequired: boolean } | null {
        const user = this.users.get(username);
        const hash = hashPassword(password, this.passwordSalt);
        const expected = user?.passwordHash ?? DUMMY_HASH;
        const a = Buffer.from(hash, 'hex');
        const b = Buffer.from(expected, 'hex');
        const valid = a.length === b.length && timingSafeEqual(a, b);
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
            expiresAt: Date.now() + this.config.consoleSessionTtlMs,
        };
        this.sessions.set(token, session);
        this.audit.record('handshake_started', { detail: `console login: ${username}` });
        return { sessionToken: token, mfaRequired: this.config.consoleMfaRequired };
    }

    verifyMfa(sessionToken: string, code: string): boolean {
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
        this.audit.record('handshake_succeeded', { detail: `console MFA ok: ${session.username}` });
        return true;
    }

    resolveSession(token: string): ConsoleSession | null {
        const session = this.sessions.get(token);
        if (!session) return null;
        if (Date.now() > session.expiresAt) {
            this.sessions.delete(token);
            return null;
        }
        if (this.config.consoleMfaRequired && !session.mfaVerified) return null;
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

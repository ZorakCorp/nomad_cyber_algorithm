import * as fs from 'fs';
import { AlgorithmSuiteId, resolveAlgorithmSuite, supportedSuiteIds } from './crypto/algorithm_suite';

function envInt(name: string, fallback: number, min = 1): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const parsed = parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed < min) return fallback;
    return parsed;
}

function envString(name: string, fallback: string): string {
    return process.env[name]?.trim() || fallback;
}

export interface NomadConfig {
    port: number;
    bindHost: string;
    healthPort: number;
    handshakeTimeoutMs: number;
    maxMessageBytes: number;
    maxConnections: number;
    maxHandshakesPerMinute: number;
    heartbeatIntervalMs: number;
    sessionTtlMs: number;
    gracefulShutdownMs: number;
    protocolVersion: number;
    algorithmSuite: AlgorithmSuiteId;
    clientAllowlist: string[];
    qsCaRootPath: string | null;
    hsmEnabled: boolean;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
    imperialCipherEnabled: boolean;
    occultVeilEnabled: boolean;
    imperialSubject: string;
    requireAllowlist: boolean;
    devMode: boolean;
    chaosModeEnabled: boolean;
    chaosJitterMs: number;
    gatewayPort: number;
    consolePort: number;
    gatewayMaxBodyBytes: number;
    consoleMfaRequired: boolean;
    consoleSessionTtlMs: number;
    vaultDir: string;
    dbVaultKeyPath: string | null;
    fileVaultKeyPath: string | null;
    redisUrl: string | null;
    webauthnRequired: boolean;
    tpmRequired: boolean;
    hsmRequired: boolean;
}

export function loadConfig(): NomadConfig {
    const allowlistRaw = process.env.NOMAD_CLIENT_ALLOWLIST?.trim();
    const devMode = process.env.NOMAD_DEV_MODE === 'true';
    const defaultSuite = devMode ? 'kyber768_dilithium3' : 'kyber1024_dilithium5';
    const suiteRaw = envString('NOMAD_ALGORITHM_SUITE', defaultSuite);
    if (!supportedSuiteIds().includes(suiteRaw as AlgorithmSuiteId)) {
        throw new Error(`Invalid NOMAD_ALGORITHM_SUITE: ${suiteRaw}. Supported: ${supportedSuiteIds().join(', ')}`);
    }
    if (!devMode && suiteRaw === 'kyber768_dilithium3') {
        throw new Error(
            'kyber768_dilithium3 is permitted only in dev/compatibility mode. ' +
            'Set NOMAD_DEV_MODE=true or use kyber1024_dilithium5 for production.'
        );
    }
    if (devMode && suiteRaw === 'kyber768_dilithium3') {
        console.warn(JSON.stringify({
            ts: new Date().toISOString(),
            level: 'warn',
            message: 'Using kyber768_dilithium3 in dev mode — not NIST production tier.',
            component: 'config',
        }));
    }
    resolveAlgorithmSuite(suiteRaw as AlgorithmSuiteId);

    return {
        port: envInt('NOMAD_PORT', 8443),
        bindHost: envString('NOMAD_BIND_HOST', '127.0.0.1'),
        healthPort: envInt('NOMAD_HEALTH_PORT', 9090),
        handshakeTimeoutMs: envInt('NOMAD_HANDSHAKE_TIMEOUT_MS', 30_000),
        maxMessageBytes: envInt('NOMAD_MAX_MESSAGE_BYTES', 1_048_576),
        maxConnections: envInt('NOMAD_MAX_CONNECTIONS', 100),
        maxHandshakesPerMinute: envInt('NOMAD_MAX_HANDSHAKES_PER_MINUTE', 60),
        heartbeatIntervalMs: envInt('NOMAD_HEARTBEAT_INTERVAL_MS', 15_000),
        sessionTtlMs: envInt('NOMAD_SESSION_TTL_MS', 300_000),
        gracefulShutdownMs: envInt('NOMAD_GRACEFUL_SHUTDOWN_MS', 10_000),
        protocolVersion: envInt('NOMAD_PROTOCOL_VERSION', 1),
        algorithmSuite: suiteRaw as AlgorithmSuiteId,
        clientAllowlist: allowlistRaw ? allowlistRaw.split(',').map((s) => s.trim()).filter(Boolean) : [],
        qsCaRootPath: process.env.NOMAD_QS_CA_ROOT_PATH?.trim() || null,
        hsmEnabled: process.env.NOMAD_HSM_ENABLED === 'true',
        logLevel: (envString('NOMAD_LOG_LEVEL', 'info') as NomadConfig['logLevel']),
        imperialCipherEnabled: process.env.NOMAD_IMPERIAL_CIPHER !== 'false',
        occultVeilEnabled: process.env.NOMAD_OCCULT_VEIL !== 'false',
        imperialSubject: envString('NOMAD_IMPERIAL_SUBJECT', 'Nomad Sovereign Channel'),
        requireAllowlist: process.env.NOMAD_REQUIRE_ALLOWLIST === 'true' || (!devMode && process.env.NOMAD_ALLOWLIST_OPEN !== 'true'),
        devMode,
        chaosModeEnabled: process.env.NOMAD_CHAOS_MODE !== 'false',
        chaosJitterMs: envInt('NOMAD_CHAOS_JITTER_MS', 40, 0),
        gatewayPort: envInt('NOMAD_GATEWAY_PORT', 8080),
        consolePort: envInt('NOMAD_CONSOLE_PORT', 8081),
        gatewayMaxBodyBytes: envInt('NOMAD_GATEWAY_MAX_BODY_BYTES', 65_536),
        consoleMfaRequired: process.env.NOMAD_CONSOLE_MFA !== 'false',
        consoleSessionTtlMs: envInt('NOMAD_CONSOLE_SESSION_TTL_MS', 900_000),
        vaultDir: envString('NOMAD_VAULT_DIR', './nomad-vault'),
        dbVaultKeyPath: process.env.NOMAD_DB_VAULT_KEY_PATH?.trim() || null,
        fileVaultKeyPath: process.env.NOMAD_FILE_VAULT_KEY_PATH?.trim() || null,
        redisUrl: process.env.NOMAD_REDIS_URL?.trim() || null,
        webauthnRequired: process.env.NOMAD_WEBAUTHN_REQUIRED !== 'false' && !devMode,
        tpmRequired: process.env.NOMAD_TPM_REQUIRED === 'true',
        hsmRequired: process.env.NOMAD_HSM_REQUIRED === 'true' || (!devMode && process.env.NOMAD_HSM_ENABLED === 'true'),
    };
}

export function loadTrustedRootFromPath(path: string): Uint8Array {
    const raw = fs.readFileSync(path, 'utf8').trim();
    const buf = Buffer.from(raw, 'base64');
    if (buf.length === 0) {
        throw new Error(`Invalid QS-CA root at ${path}`);
    }
    return new Uint8Array(buf);
}

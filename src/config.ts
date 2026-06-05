import { AlgorithmSuiteId } from './crypto/algorithm_suite';

function envInt(name: string, fallback: number): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const parsed = parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
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
}

export function loadConfig(): NomadConfig {
    const allowlistRaw = process.env.NOMAD_CLIENT_ALLOWLIST?.trim();
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
        algorithmSuite: envString('NOMAD_ALGORITHM_SUITE', 'kyber768_dilithium3') as AlgorithmSuiteId,
        clientAllowlist: allowlistRaw ? allowlistRaw.split(',').map((s) => s.trim()).filter(Boolean) : [],
        qsCaRootPath: process.env.NOMAD_QS_CA_ROOT_PATH?.trim() || null,
        hsmEnabled: process.env.NOMAD_HSM_ENABLED === 'true',
        logLevel: (envString('NOMAD_LOG_LEVEL', 'info') as NomadConfig['logLevel']),
        imperialCipherEnabled: process.env.NOMAD_IMPERIAL_CIPHER !== 'false',
        occultVeilEnabled: process.env.NOMAD_OCCULT_VEIL !== 'false',
        imperialSubject: envString('NOMAD_IMPERIAL_SUBJECT', 'Nomad Sovereign Channel'),
    };
}

import { AuditEvent, AuditEventType } from './audit_log';

/** Laplace mechanism — NIST SP 800-188 differential privacy for audit aggregates. */
export function laplaceNoise(sensitivity: number, epsilon: number): number {
    const u = Math.random() - 0.5;
    const scale = sensitivity / epsilon;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
}

export interface DpAggregateQuery {
    eventType?: AuditEventType;
    groupBy?: 'type' | 'hour';
    epsilon?: number;
}

export interface DpAggregateResult {
    noisyCount: number;
    trueCount: number;
    epsilon: number;
    sensitivity: number;
    mechanism: 'laplace';
}

const DEFAULT_EPSILON = 1.0;
const COUNT_SENSITIVITY = 1;

export function dpAggregateCount(events: AuditEvent[], query: DpAggregateQuery = {}): DpAggregateResult {
    const epsilon = query.epsilon ?? DEFAULT_EPSILON;
    let filtered = events;
    if (query.eventType) {
        filtered = events.filter((e) => e.type === query.eventType);
    }
    const trueCount = filtered.length;
    const noisyCount = Math.max(0, Math.round(trueCount + laplaceNoise(COUNT_SENSITIVITY, epsilon)));
    return {
        noisyCount,
        trueCount,
        epsilon,
        sensitivity: COUNT_SENSITIVITY,
        mechanism: 'laplace',
    };
}

export function dpExportEvents(events: AuditEvent[], limit = 100, epsilon = DEFAULT_EPSILON): {
    aggregates: DpAggregateResult[];
    exportedAt: string;
} {
    const types: AuditEventType[] = [
        'handshake_succeeded',
        'handshake_failed',
        'rate_limit_exceeded',
        'replay_detected',
    ];
    const aggregates = types.map((eventType) => dpAggregateCount(events, { eventType, epsilon }));
    return { aggregates, exportedAt: new Date().toISOString() };
}

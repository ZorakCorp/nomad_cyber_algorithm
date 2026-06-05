export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

export interface LogContext {
    correlationId?: string;
    component?: string;
    operation?: string;
    [key: string]: unknown;
}

export class StructuredLogger {
    constructor(private minLevel: LogLevel = 'info') {}

    private emit(level: LogLevel, message: string, context: LogContext = {}): void {
        if (LEVEL_ORDER[level] < LEVEL_ORDER[this.minLevel]) return;
        const entry = {
            ts: new Date().toISOString(),
            level,
            message,
            ...context,
        };
        const line = JSON.stringify(entry);
        if (level === 'error') {
            console.error(line);
        } else if (level === 'warn') {
            console.warn(line);
        } else {
            console.log(line);
        }
    }

    debug(message: string, context?: LogContext): void { this.emit('debug', message, context); }
    info(message: string, context?: LogContext): void { this.emit('info', message, context); }
    warn(message: string, context?: LogContext): void { this.emit('warn', message, context); }
    error(message: string, context?: LogContext): void { this.emit('error', message, context); }
}

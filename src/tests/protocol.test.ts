import { attachSecurityFields, parseWireMessage, serializeMessage } from '../protocol';
import { validateWireMessage } from '../schema';
import { frameMessage, parseMessages, setMaxMessageBytes } from '../utils';
import { ReplayGuard } from '../security/replay_guard';
import { RateLimiter } from '../security/rate_limiter';
import { assert, assertThrows, runTests, TestCase } from './test_runner';

const tests: TestCase[] = [
    {
        name: 'attachSecurityFields adds version, nonce, timestamp',
        fn: () => {
            const msg = attachSecurityFields({ type: 'client_hello' }, 'abc');
            assert(msg.protocolVersion === 1, 'version');
            assert(!!msg.nonce, 'nonce');
            assert(!!msg.timestamp, 'timestamp');
            validateWireMessage(msg);
        },
    },
    {
        name: 'schema rejects unknown fields',
        fn: () => {
            const msg = attachSecurityFields({ type: 'client_hello', evil: 'x' } as never, 'id');
            assertThrows(() => validateWireMessage(msg), 'unknown field');
        },
    },
    {
        name: 'schema rejects unsupported protocol version',
        fn: () => {
            const msg = {
                type: 'client_hello' as const,
                protocolVersion: 99,
                correlationId: 'id',
                nonce: 'abc',
                timestamp: Date.now(),
            };
            assertThrows(() => validateWireMessage(msg));
        },
    },
    {
        name: 'frame round-trip preserves payload',
        fn: () => {
            const payload = serializeMessage(attachSecurityFields({ type: 'client_hello' }, 'cid'));
            const framed = frameMessage(payload);
            let out: Buffer = Buffer.alloc(0);
            out = parseMessages(framed, (m) => {
                const parsed = parseWireMessage(m);
                assert(parsed.type === 'client_hello', 'type');
            });
            assert(out.length === 0, 'buffer drained');
        },
    },
    {
        name: 'frame rejects oversized length prefix',
        fn: () => {
            setMaxMessageBytes(100);
            const buf = Buffer.alloc(8);
            buf.writeUInt32BE(200, 0);
            assertThrows(() => parseMessages(buf, () => {}));
            setMaxMessageBytes(1_048_576);
        },
    },
    {
        name: 'replay guard rejects duplicate nonce',
        fn: () => {
            const guard = new ReplayGuard();
            guard.validate('n1', Date.now(), 'c1');
            assertThrows(() => guard.validate('n1', Date.now(), 'c1'));
        },
    },
    {
        name: 'replay guard rejects stale timestamp',
        fn: () => {
            const guard = new ReplayGuard({ maxClockSkewMs: 1000, nonceTtlMs: 5000, maxEntries: 1000 });
            assertThrows(() => guard.validate('n2', Date.now() - 60_000, 'c1'));
        },
    },
    {
        name: 'rate limiter enforces connection cap',
        fn: () => {
            const rl = new RateLimiter(1, 100);
            assert(rl.tryAcquireConnection(), 'first');
            assert(!rl.tryAcquireConnection(), 'second blocked');
            rl.releaseConnection();
            assert(rl.tryAcquireConnection(), 'after release');
        },
    },
    {
        name: 'rate limiter enforces handshake rate',
        fn: () => {
            const rl = new RateLimiter(10, 2);
            assert(rl.tryAcquireHandshake(), 'h1');
            assert(rl.tryAcquireHandshake(), 'h2');
            assert(!rl.tryAcquireHandshake(), 'h3 blocked');
        },
    },
];

runTests(tests);

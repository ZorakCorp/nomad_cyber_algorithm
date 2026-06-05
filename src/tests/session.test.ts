import { SessionStore } from '../session/session_store';
import { ClientSessionCache } from '../session/client_session_cache';
import { assert, runTests, TestCase } from './test_runner';

const tests: TestCase[] = [
    {
        name: 'session store issue and redeem round-trip',
        fn: () => {
            const store = new SessionStore(Buffer.alloc(32, 7));
            const key = Buffer.alloc(32, 7);
            const ticket = store.issue('corr-1', key, 'clientpk', 'serverpk', 60_000);
            const payload = store.redeem(ticket);
            assert(!!payload, 'redeemed');
            assert(payload!.correlationId === 'corr-1', 'correlation');
            assert(payload!.aesKeyHex === key.toString('hex'), 'key');
            assert(payload!.serverSigPublicKey === 'serverpk', 'server pk');
        },
    },
    {
        name: 'session store rejects tampered ticket',
        fn: () => {
            const store = new SessionStore(Buffer.alloc(32, 7));
            const ticket = store.issue('c', Buffer.alloc(32), 'pk', 'spk', 60_000);
            const tampered = ticket.slice(0, -4) + 'AAAA';
            assert(store.redeem(tampered) === null, 'tampered');
        },
    },
    {
        name: 'client session cache respects TTL',
        fn: () => {
            const cache = new ClientSessionCache();
            const key = Buffer.alloc(32, 1);
            cache.save('t1', key, 'c1', 's1');
            assert(!!cache.load('t1', 60_000), 'fresh');
            assert(cache.load('t1', -1) === null, 'expired');
        },
    },
];

runTests(tests);

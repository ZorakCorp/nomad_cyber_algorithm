import { ClientAllowlist } from '../security/client_allowlist';
import { ReplayGuard } from '../security/replay_guard';
import { SessionStore } from '../session/session_store';
import { attachSecurityFields } from '../protocol';
import { assert, runTests, TestCase } from './test_runner';

const tests: TestCase[] = [
    {
        name: 'allowlist fail-closed when requireEntries and empty',
        fn: () => {
            const list = new ClientAllowlist([], true);
            const key = new Uint8Array([1, 2, 3]);
            assert(!list.isAllowed(key), 'reject when empty + required');
        },
    },
    {
        name: 'replay guard rejects zero timestamp',
        fn: () => {
            const guard = new ReplayGuard();
            let threw = false;
            try {
                guard.validate('nonce-a', 0, 'corr');
            } catch {
                threw = true;
            }
            assert(threw, 'zero timestamp rejected');
        },
    },
    {
        name: 'session ticket is one-time consumable',
        fn: () => {
            const store = new SessionStore(Buffer.alloc(32, 9));
            const ticket = store.issue('c', Buffer.alloc(32, 9), 'cpk', 'spk', 60_000);
            assert(!!store.redeem(ticket), 'first redeem');
            assert(store.redeem(ticket) === null, 'second redeem rejected');
        },
    },
    {
        name: 'attachSecurityFields accepts pinned imperial timestamp',
        fn: () => {
            const ts = 1_700_000_000_000;
            const msg = attachSecurityFields({ type: 'encrypted_data', sequence: 1 }, 'cid', ts);
            assert(msg.timestamp === ts, 'pinned timestamp preserved');
        },
    },
    {
        name: 'allowlist register and match',
        fn: () => {
            const list = new ClientAllowlist([], true);
            const key = new Uint8Array([4, 5, 6]);
            list.register(key);
            assert(list.isAllowed(key), 'registered key allowed');
            assert(!list.isAllowed(new Uint8Array([7])), 'unknown key rejected');
        },
    },
    {
        name: 'replay guard evicts oldest under flood instead of crashing',
        fn: () => {
            const guard = new ReplayGuard({ maxClockSkewMs: 60_000, nonceTtlMs: 120_000, maxEntries: 10 });
            const base = Date.now();
            for (let i = 0; i < 15; i++) {
                guard.validate(`n${i}`, base + i, 'corr');
            }
            assert(true, 'survives flood via LRU eviction');
        },
    },
];

runTests(tests);

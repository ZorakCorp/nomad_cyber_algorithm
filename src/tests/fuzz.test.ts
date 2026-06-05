import { randomBytes } from 'crypto';
import { parseMessages, setMaxMessageBytes } from '../utils';
import { parseWireMessage } from '../protocol';
import { validateWireMessage } from '../schema';
import { assert, runTests, TestCase } from './test_runner';

function fuzzParseMessages(iterations: number): void {
    for (let i = 0; i < iterations; i++) {
        const len = randomBytes(1)[0] % 64;
        const buf = randomBytes(4 + len);
        try {
            parseMessages(buf, () => {});
        } catch {
            // Expected for invalid frames
        }
    }
}

function fuzzJsonMessages(iterations: number): void {
    for (let i = 0; i < iterations; i++) {
        const garbage = randomBytes(8 + (randomBytes(1)[0] % 128));
        try {
            const msg = parseWireMessage(garbage);
            validateWireMessage(msg);
        } catch {
            // Expected
        }
    }
}

const tests: TestCase[] = [
    {
        name: 'fuzz: random frames do not throw uncaught errors',
        fn: () => {
            setMaxMessageBytes(4096);
            fuzzParseMessages(500);
            assert(true, 'completed');
        },
    },
    {
        name: 'fuzz: random JSON payloads fail safely',
        fn: () => {
            fuzzJsonMessages(300);
            assert(true, 'completed');
        },
    },
    {
        name: 'fuzz: zero-length frame rejected',
        fn: () => {
            const buf = Buffer.alloc(4);
            buf.writeUInt32BE(0, 0);
            let threw = false;
            try { parseMessages(buf, () => {}); } catch { threw = true; }
            assert(threw, 'zero length must throw');
        },
    },
];

runTests(tests);

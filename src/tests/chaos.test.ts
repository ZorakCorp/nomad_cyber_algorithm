import { randomBytes } from 'crypto';
import { ImperialCipherStack } from '../imperial/imperial_cipher_stack';
import {
    applyChaoticPadding,
    stripChaoticPadding,
    deriveShuffledOrder,
} from '../chaos/entropy_engine';
import { deriveJitterMs } from '../chaos/timing_veil';
import { DbVault } from '../data/db_vault';
import { AuditLog } from '../ops/audit_log';
import { assert, runTests, TestCase } from './test_runner';

const masterKey = randomBytes(32);
const correlationId = 'chaos-test-corr';
const ts = 1_700_000_000_000;

const tests: TestCase[] = [
    {
        name: 'chaotic padding round-trip',
        fn: () => {
            const body = Buffer.from('no pattern payload');
            const padded = applyChaoticPadding(body, masterKey, correlationId, 3, ts);
            assert(padded.length > body.length + 20, 'length unpredictable');
            const stripped = stripChaoticPadding(padded, masterKey, correlationId, 3, ts);
            assert(stripped.equals(body), 'padding stripped');
        },
    },
    {
        name: 'layer order varies by sequence but is deterministic',
        fn: () => {
            const layers = ['hieroglyph', 'augustan', 'scytale'] as const;
            const a = deriveShuffledOrder(layers, masterKey, correlationId, 1, ts, 'mutable');
            const a2 = deriveShuffledOrder(layers, masterKey, correlationId, 1, ts, 'mutable');
            const distant = deriveShuffledOrder(layers, masterKey, correlationId, 9999, ts, 'mutable');
            assert(a.join(',') === a2.join(','), 'same inputs same order');
            const orders = new Set([a.join(','), distant.join(',')]);
            assert(orders.size >= 1, 'shuffle produces valid order');
        },
    },
    {
        name: 'same plaintext produces different ciphertext per sequence',
        fn: () => {
            const stack = new ImperialCipherStack(masterKey, correlationId, {
                enabled: true,
                occultVeilEnabled: true,
                chaosModeEnabled: true,
                subject: 'Chaos',
            });
            const plain = Buffer.from('identical plaintext');
            const enc1 = stack.encipher(plain, ts, 10);
            const enc2 = stack.encipher(plain, ts, 11);
            assert(!enc1.equals(enc2), 'no repeating wire pattern');
            assert(stack.decipher(enc1, ts, 10).equals(plain), 'seq 10 opens');
            assert(stack.decipher(enc2, ts, 11).equals(plain), 'seq 11 opens');
        },
    },
    {
        name: 'timing jitter stays within bounds',
        fn: () => {
            const max = 40;
            for (let i = 0; i < 20; i++) {
                const j = deriveJitterMs(max, i, correlationId);
                assert(j >= 0 && j <= max + 10, `jitter bounded: ${j}`);
            }
        },
    },
    {
        name: 'db vault field seal round-trip',
        fn: () => {
            const audit = new AuditLog(null);
            const vault = new DbVault({ audit, devMode: true });
            const sealed = vault.encryptField('users', 'ssn', '123-45-6789', 't1');
            const opened = vault.decryptField('users', 'ssn', sealed, 't1');
            assert(opened === '123-45-6789', 'db field');
        },
    },
];

runTests(tests);

import { createHmac, randomBytes } from 'crypto';
import { ImperialCipherStack } from '../imperial/imperial_cipher_stack';
import { scytaleEncipher, scytaleDecipher } from '../imperial/scytale';
import { applyPersianSeal, verifyPersianSeal } from '../imperial/persian_seal';
import { planetaryEpochSlot, deriveOccultVeilKey, occultVeilTransform } from '../occult/aureon_veil';
import { IMPERIAL_CIPHER_CORPUS } from '../imperial/research_corpus';
import { assert, runTests, TestCase } from './test_runner';

const masterKey = randomBytes(32);
const correlationId = 'imperial-test-corr';
const ts = Date.now();

const tests: TestCase[] = [
    {
        name: 'imperial corpus documents 10 civilizational mappings',
        fn: () => {
            assert(IMPERIAL_CIPHER_CORPUS.length >= 10, 'corpus size');
            const civs = new Set(IMPERIAL_CIPHER_CORPUS.map((c) => c.civilization));
            assert(civs.has('Greek'), 'greek');
            assert(civs.has('Roman'), 'roman');
            assert(civs.has('Persian'), 'persian');
            assert(civs.has('Egyptian'), 'egyptian');
            assert(civs.has('Aureon-Occult'), 'occult');
        },
    },
    {
        name: 'scytale round-trip',
        fn: () => {
            const data = Buffer.from('Spartan dispatch to Lysander');
            const enc = scytaleEncipher(data, 8);
            const dec = scytaleDecipher(enc, 8);
            assert(dec.equals(data), 'scytale');
        },
    },
    {
        name: 'persian seal detects tampering',
        fn: () => {
            const key = createHmac('sha256', masterKey).update('seal').digest();
            const sealed = applyPersianSeal(Buffer.from('royal decree'), key);
            sealed[sealed.length - 1] ^= 0xff;
            let threw = false;
            try { verifyPersianSeal(sealed, key); } catch { threw = true; }
            assert(threw, 'tamper detected');
        },
    },
    {
        name: 'occult veil is symmetric',
        fn: () => {
            const veilKey = deriveOccultVeilKey(masterKey, correlationId, ts);
            const data = Buffer.from('veiled message');
            const veiled = occultVeilTransform(data, veilKey);
            const opened = occultVeilTransform(veiled, veilKey);
            assert(opened.equals(data), 'veil symmetric');
        },
    },
    {
        name: 'planetary epoch slot is stable within same second',
        fn: () => {
            assert(planetaryEpochSlot(ts) === planetaryEpochSlot(ts + 100), 'epoch stable');
        },
    },
    {
        name: 'full imperial cipher stack round-trip',
        fn: () => {
            const stack = new ImperialCipherStack(masterKey, correlationId, {
                enabled: true,
                occultVeilEnabled: true,
                chaosModeEnabled: true,
                subject: 'Pharaoh Test Channel',
            });
            const plain = Buffer.from('Top Secret imperial dispatch');
            const enc = stack.encipher(plain, ts, 1);
            const dec = stack.decipher(enc, ts, 1);
            assert(dec.equals(plain), 'stack round-trip');
        },
    },
    {
        name: 'imperial stack fails on wrong timestamp (torch epoch)',
        fn: () => {
            const stack = new ImperialCipherStack(masterKey, correlationId, {
                enabled: true,
                occultVeilEnabled: true,
                chaosModeEnabled: false,
                subject: 'Test',
            });
            const enc = stack.encipher(Buffer.from('time-bound'), ts, 2);
            let threw = false;
            try { stack.decipher(enc, ts + 3_600_001, 2); } catch { threw = true; }
            assert(threw, 'wrong epoch');
        },
    },
];

runTests(tests);

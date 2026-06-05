import { randomBytes } from 'crypto';
import { assert, runTests, TestCase } from './test_runner';
import { AuditLog } from '../ops/audit_log';
import { splitSecret, combineShares } from '../crypto/shamir';
import { CertificateTransparencyLog } from '../crypto/ct_log';
import { dpAggregateCount } from '../ops/dp_audit_export';
import { ThresholdSigCoordinator } from '../crypto/threshold_sig';
import { requireTpmAttestation } from '../startup/tpm_attest';
import { loadConfig } from '../config';
import { applyTestConsoleEnv } from './test_credentials';
import { ConsoleAuthService } from '../console/console_auth';
import { ZkAuthService, ZkAuthService as Zk } from '../console/zk_auth';
import { ed25519 } from '@noble/curves/ed25519';

const tests: TestCase[] = [
    {
        name: 'audit log chained HMAC verifyChain passes',
        fn: () => {
            process.env.NOMAD_AUDIT_CHAIN_KEY = randomBytes(32).toString('hex');
            const log = new AuditLog(null);
            log.record('handshake_started', { detail: 'a' });
            log.record('handshake_succeeded', { detail: 'b' });
            const result = log.verifyChain();
            assert(result.valid, `chain valid: ${result.errors.join(', ')}`);
        },
    },
    {
        name: 'Shamir 3-of-5 split and combine recovers secret',
        fn: () => {
            const secret = randomBytes(32);
            const shares = splitSecret(secret, 3, 5);
            const recovered = combineShares([shares[0], shares[2], shares[4]]);
            assert(Buffer.from(recovered).equals(secret), 'secret recovered');
        },
    },
    {
        name: 'CT log append and verifyChain',
        fn: () => {
            const ct = new CertificateTransparencyLog(null);
            const cert = {
                version: 1,
                subject: 'test',
                issuer: 'root',
                sigPublicKey: 'aa',
                kemPublicKey: 'bb',
                notBefore: Date.now(),
                notAfter: Date.now() + 1000,
                signature: 'cc',
            };
            ct.append(cert, new Uint8Array([1, 2, 3]));
            const v = ct.verifyChain();
            assert(v.valid, v.errors.join(', '));
        },
    },
    {
        name: 'DP audit export Laplace noise bounded',
        fn: () => {
            const events = Array.from({ length: 50 }, (_, i) => ({
                id: String(i),
                ts: new Date().toISOString(),
                type: 'handshake_succeeded' as const,
                prevEntryId: '',
                entryMac: '',
            }));
            const r = dpAggregateCount(events, { epsilon: 1.0 });
            assert(r.trueCount === 50, 'true count');
            assert(r.noisyCount >= 0, 'non-negative noisy count');
        },
    },
    {
        name: 'threshold sig 2-of-3 produces signature',
        fn: () => {
            const coord = new ThresholdSigCoordinator(2, 3);
            coord.distributeShares(randomBytes(32), ['n1', 'n2', 'n3']);
            coord.beginSigning('req1', Buffer.from('message'), ['n1', 'n2', 'n3']);
            const sig = coord.combineThresholdSignature('req1', ['n1', 'n2']);
            assert(sig.signature.length === 32, 'signature length');
            assert(sig.participants.length === 2, 'two participants');
        },
    },
    {
        name: 'production config enforces kyber1024_dilithium5',
        fn: () => {
            const prevDev = process.env.NOMAD_DEV_MODE;
            const prevSuite = process.env.NOMAD_ALGORITHM_SUITE;
            delete process.env.NOMAD_DEV_MODE;
            delete process.env.NOMAD_ALGORITHM_SUITE;
            try {
                const cfg = loadConfig();
                assert(cfg.algorithmSuite === 'kyber1024_dilithium5', 'prod default suite');
            } finally {
                if (prevDev) process.env.NOMAD_DEV_MODE = prevDev;
                else delete process.env.NOMAD_DEV_MODE;
                if (prevSuite) process.env.NOMAD_ALGORITHM_SUITE = prevSuite;
                else delete process.env.NOMAD_ALGORITHM_SUITE;
            }
        },
    },
    {
        name: 'dev mode rejects kyber768 without NOMAD_DEV_MODE',
        fn: () => {
            const prev = process.env.NOMAD_ALGORITHM_SUITE;
            process.env.NOMAD_ALGORITHM_SUITE = 'kyber768_dilithium3';
            delete process.env.NOMAD_DEV_MODE;
            let threw = false;
            try {
                loadConfig();
            } catch {
                threw = true;
            }
            if (prev) process.env.NOMAD_ALGORITHM_SUITE = prev;
            else delete process.env.NOMAD_ALGORITHM_SUITE;
            assert(threw, '768 blocked in prod');
        },
    },
    {
        name: 'Argon2id password hash and verify',
        fn: async () => {
            applyTestConsoleEnv();
            const audit = new AuditLog(null);
            const auth = await ConsoleAuthService.create(loadConfig(), audit);
            const login = await auth.login('admin', process.env.NOMAD_CONSOLE_ADMIN_PASSWORD!);
            assert(login !== null, 'login succeeds with argon2');
        },
    },
    {
        name: 'ZK sovereign proof round-trip',
        fn: () => {
            const audit = new AuditLog(null);
            const zk = new ZkAuthService(audit);
            const priv = ed25519.utils.randomPrivateKey();
            const pub = ed25519.getPublicKey(priv);
            zk.setSovereignPublicKey(pub);
            const challenge = zk.issueChallenge('admin');
            const nonce = zk.getChallengeNonce(challenge.challengeId)!;
            const proof = Zk.generateProof(priv, challenge, nonce);
            assert(zk.verifyProof('admin', proof), 'ZK proof verifies');
        },
    },
    {
        name: 'TPM attestation skipped when not configured',
        fn: () => {
            delete process.env.NOMAD_TPM_REQUIRED;
            const r = requireTpmAttestation(true);
            assert(r.attested, 'dev skip ok');
        },
    },
];

void runTests(tests);

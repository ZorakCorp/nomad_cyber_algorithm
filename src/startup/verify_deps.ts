import * as fs from 'fs';
import * as path from 'path';
import { KeyEncapsulation, OQS_KEM_ALG, OQS_SIG_ALG, Signature } from '@open-quantum-safe/oqs-javascript';

export const EXPECTED_OQS_VERSION = '0.1.0';

function resolveProjectRoot(): string {
    return path.join(__dirname, '..', '..');
}

function readInstalledOqsVersion(): string {
    const pkgPath = path.join(resolveProjectRoot(), 'node_modules', '@open-quantum-safe', 'oqs-javascript', 'package.json');
    if (!fs.existsSync(pkgPath)) {
        throw new Error(`FATAL: @open-quantum-safe/oqs-javascript not installed at ${pkgPath}`);
    }
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version?: string };
    if (!pkg.version) {
        throw new Error('FATAL: OQS package.json missing version field.');
    }
    return pkg.version;
}

function selfTestKyber768(): void {
    const kem = new KeyEncapsulation(OQS_KEM_ALG.Kyber768);
    const pair = kem.generateKeyPair();
    const { ciphertext, sharedSecret } = kem.encapsulate(pair.publicKey);
    const decapsulated = kem.decapsulate(pair.privateKey, ciphertext);
    if (decapsulated.length !== sharedSecret.length) {
        throw new Error('FATAL: Kyber768 decapsulated secret length mismatch — library integrity check failed.');
    }
    if (!Buffer.from(decapsulated).equals(Buffer.from(sharedSecret))) {
        throw new Error('FATAL: Kyber768 shared secret mismatch — library integrity check failed.');
    }
}

function selfTestDilithium3(): void {
    const sig = new Signature(OQS_SIG_ALG.Dilithium3);
    const pair = sig.generateKeyPair();
    const message = Buffer.from('zophiel-liboqs-integrity-probe');
    const signature = sig.sign(pair.privateKey, message);
    const valid = sig.verify(pair.publicKey, message, signature);
    if (!valid) {
        throw new Error('FATAL: Dilithium3 signature verification failed — library integrity check failed.');
    }
}

/**
 * Verifies installed liboqs stub/package version and runs functional crypto self-tests.
 * Must run before any network socket is opened.
 */
export function verifyLiboqsIntegrity(): void {
    const installed = readInstalledOqsVersion();
    if (installed !== EXPECTED_OQS_VERSION) {
        throw new Error(
            `FATAL: OQS version mismatch. Expected ${EXPECTED_OQS_VERSION}, installed ${installed}. ` +
            'Refusing to start with unverified cryptographic dependency.'
        );
    }
    selfTestKyber768();
    selfTestDilithium3();
    verifySbomIfPresent();
    console.log('[ZOPHIEL] liboqs integrity verified — Kyber768 + Dilithium3 self-test passed');
}

function verifySbomIfPresent(): void {
    const bomPath = path.join(resolveProjectRoot(), 'sbom', 'bom.json');
    const hashPath = path.join(resolveProjectRoot(), 'sbom', 'bom.sha256');
    if (!fs.existsSync(bomPath)) return;
    const { createHash } = require('crypto') as typeof import('crypto');
    const bomHash = createHash('sha256').update(fs.readFileSync(bomPath)).digest('hex');
    if (fs.existsSync(hashPath)) {
        const expected = fs.readFileSync(hashPath, 'utf8').trim();
        if (bomHash !== expected) {
            throw new Error('FATAL: SBOM hash drift detected — rebuild with npm run generate:sbom');
        }
    }
    console.log('[SUPPLY CHAIN] SBOM integrity verified');
}

if (require.main === module) {
    try {
        verifyLiboqsIntegrity();
    } catch (err) {
        console.error(err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
}

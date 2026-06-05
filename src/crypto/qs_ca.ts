import { Signature } from '@open-quantum-safe/oqs-javascript';
import { CryptoService } from './crypto_service';
import { encodeBinary, decodeBinary } from '../protocol';
import { CertificateTransparencyLog } from './ct_log';

export interface PQCertificatePayload {
    version: number;
    subject: string;
    issuer: string;
    sigPublicKey: string;
    kemPublicKey: string;
    notBefore: number;
    notAfter: number;
}

export interface PQCertificate extends PQCertificatePayload {
    signature: string;
}

export interface AirGapBundle {
    rootPublicKey: string;
    certificate: PQCertificate;
    exportedAt: number;
}

export class QuantumSafeCA {
    private rootSig: Signature;
    rootPublicKey: Uint8Array;
    private rootPrivateKey: Uint8Array;
    private pinnedServerKeys: Set<string> = new Set();
    readonly ctLog: CertificateTransparencyLog;

    constructor(
        private crypto: CryptoService,
        subject: string = 'Nomad QS-CA Root',
        trustedRootPublicKey?: Uint8Array,
        ctLog?: CertificateTransparencyLog
    ) {
        this.ctLog = ctLog ?? new CertificateTransparencyLog();
        this.rootSig = crypto.createSig();
        if (trustedRootPublicKey) {
            this.rootPublicKey = trustedRootPublicKey;
            this.rootPrivateKey = new Uint8Array(0);
        } else {
            const rootPair = crypto.generateSigKeyPair(this.rootSig);
            this.rootPublicKey = rootPair.publicKey;
            this.rootPrivateKey = rootPair.privateKey;
        }
    }

    static fromTrustedRoot(crypto: CryptoService, rootPublicKey: Uint8Array): QuantumSafeCA {
        return new QuantumSafeCA(crypto, 'Trusted QS-CA Root', rootPublicKey);
    }

    pinServerKey(sigPublicKey: Uint8Array): void {
        this.pinnedServerKeys.add(encodeBinary(sigPublicKey));
    }

    issueCertificate(
        subject: string,
        sigPublicKey: Uint8Array,
        kemPublicKey: Uint8Array,
        ttlMs: number = 86_400_000
    ): PQCertificate {
        const now = Date.now();
        const payload: PQCertificatePayload = {
            version: 1,
            subject,
            issuer: 'Nomad QS-CA Root',
            sigPublicKey: encodeBinary(sigPublicKey),
            kemPublicKey: encodeBinary(kemPublicKey),
            notBefore: now,
            notAfter: now + ttlMs,
        };
        const canonical = Buffer.from(JSON.stringify(payload));
        const signature = this.crypto.sign(this.rootSig, this.rootPrivateKey, canonical);
        const cert = { ...payload, signature: encodeBinary(signature) };
        this.ctLog.append(cert, signature);
        return cert;
    }

    verifyCertificate(cert: PQCertificate): boolean {
        const now = Date.now();
        if (now < cert.notBefore || now > cert.notAfter) {
            return false;
        }

        const { signature, ...payload } = cert;
        const canonical = Buffer.from(JSON.stringify(payload));
        const sigBytes = decodeBinary(signature, 'certificate.signature');
        const valid = this.crypto.verify(this.rootSig, this.rootPublicKey, canonical, sigBytes);

        if (!valid) return false;

        if (this.pinnedServerKeys.size > 0) {
            return this.pinnedServerKeys.has(cert.sigPublicKey);
        }
        return true;
    }

    exportAirGapBundle(certificate: PQCertificate): AirGapBundle {
        return {
            rootPublicKey: encodeBinary(this.rootPublicKey),
            certificate,
            exportedAt: Date.now(),
        };
    }

    importAirGapBundle(bundle: AirGapBundle): void {
        if (!this.verifyCertificate(bundle.certificate)) {
            throw new Error('Air-gap bundle certificate failed QS-CA verification.');
        }
        this.pinServerKey(decodeBinary(bundle.certificate.sigPublicKey, 'sigPublicKey'));
    }
}

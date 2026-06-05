import { createHash } from 'crypto';
import { PQCertificate } from './qs_ca';
import { CryptoService } from './crypto_service';
import { encodeBinary, decodeBinary } from '../protocol';

export type OcspStatus = 'good' | 'revoked' | 'unknown';

export interface OcspResponse {
    status: OcspStatus;
    certFingerprint: string;
    thisUpdate: number;
    nextUpdate: number;
    stapledSignature: string;
}

export class OcspResponder {
    private revoked = new Set<string>();
    private stapled = new Map<string, OcspResponse>();

    constructor(
        private crypto: CryptoService,
        private responderPrivateKey: Uint8Array,
        private responderPublicKey: Uint8Array
    ) {}

    certFingerprint(cert: PQCertificate): string {
        return createHash('sha256')
            .update(cert.sigPublicKey)
            .update(cert.kemPublicKey)
            .digest('hex');
    }

    revoke(cert: PQCertificate): void {
        this.revoked.add(this.certFingerprint(cert));
        this.stapled.delete(this.certFingerprint(cert));
    }

    respond(cert: PQCertificate): OcspResponse {
        const fp = this.certFingerprint(cert);
        const now = Date.now();
        let status: OcspStatus = 'good';
        if (this.revoked.has(fp)) status = 'revoked';
        if (now > cert.notAfter || now < cert.notBefore) status = 'revoked';

        const payload = JSON.stringify({
            status,
            certFingerprint: fp,
            thisUpdate: now,
            nextUpdate: now + 3_600_000,
        });
        const sig = this.crypto.createSig();
        const signature = this.crypto.sign(sig, this.responderPrivateKey, Buffer.from(payload));
        const response: OcspResponse = {
            status,
            certFingerprint: fp,
            thisUpdate: now,
            nextUpdate: now + 3_600_000,
            stapledSignature: encodeBinary(signature),
        };
        this.stapled.set(fp, response);
        return response;
    }

    getStapledResponse(cert: PQCertificate): OcspResponse | null {
        return this.stapled.get(this.certFingerprint(cert)) ?? null;
    }

    verifyStapled(response: OcspResponse): boolean {
        const { stapledSignature, ...payload } = response;
        const canonical = Buffer.from(JSON.stringify(payload));
        const sigBytes = decodeBinary(stapledSignature, 'stapledSignature');
        const sig = this.crypto.createSig();
        return this.crypto.verify(sig, this.responderPublicKey, canonical, sigBytes);
    }
}

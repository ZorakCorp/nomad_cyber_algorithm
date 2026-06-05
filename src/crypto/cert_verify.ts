import { Signature } from '@open-quantum-safe/oqs-javascript';
import { CryptoService } from './crypto_service';
import { QuantumSafeCA, PQCertificate } from './qs_ca';
import { decodeBinary } from '../protocol';

export function verifyServerHelloIdentity(
    cert: PQCertificate,
    helloKemPublicKey: Uint8Array,
    helloSigPublicKey: Uint8Array,
    qsCa: QuantumSafeCA
): boolean {
    if (!qsCa.verifyCertificate(cert)) {
        return false;
    }
    const certKem = decodeBinary(cert.kemPublicKey, 'cert.kemPublicKey');
    const certSig = decodeBinary(cert.sigPublicKey, 'cert.sigPublicKey');
    if (Buffer.from(certKem).compare(Buffer.from(helloKemPublicKey)) !== 0) {
        return false;
    }
    if (Buffer.from(certSig).compare(Buffer.from(helloSigPublicKey)) !== 0) {
        return false;
    }
    return true;
}

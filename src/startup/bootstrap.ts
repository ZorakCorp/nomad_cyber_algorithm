import { verifyLiboqsIntegrity } from './verify_deps';
import { requireTpmAttestation } from './tpm_attest';
import { loadConfig } from '../config';
import { createHsmProvider } from '../crypto/pkcs11_hsm';

/**
 * Ordered startup sequence — must complete before any key material loads:
 * 1. liboqs integrity + self-test
 * 2. TPM 2.0 boot attestation (PCR baseline)
 * 3. HSM connectivity (when required)
 * 4. Config load with production suite guard
 */
export async function bootstrapStartup(): Promise<ReturnType<typeof loadConfig>> {
    verifyLiboqsIntegrity();
    const devMode = process.env.NOMAD_DEV_MODE === 'true';
    requireTpmAttestation(devMode);

    const config = loadConfig();
    if (config.hsmRequired || config.hsmEnabled) {
        const provider = createHsmProvider();
        await provider.connect();
        console.log(`[HSM] Connected via ${provider.vendor} — private keys non-extractable`);
    }

    return config;
}

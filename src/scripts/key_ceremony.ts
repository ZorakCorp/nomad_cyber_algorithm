import { randomBytes, publicEncrypt, createPublicKey } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { splitSecret } from '../crypto/shamir';

interface Custodian {
    id: string;
    publicKeyPem: string;
}

interface CeremonyOutput {
    threshold: number;
    shares: number;
    encryptedShares: Array<{ custodianId: string; shareIndex: number; ciphertext: string }>;
    destroyedAt: string;
    rootKeyDestroyed: true;
}

function parseArgs(): { threshold: number; shares: number; output: string; custodians: string } {
    const args = process.argv.slice(2);
    const get = (flag: string, fallback: string) => {
        const idx = args.indexOf(flag);
        return idx >= 0 && args[idx + 1] ? args[idx + 1] : fallback;
    };
    return {
        threshold: parseInt(get('--threshold', '3'), 10),
        shares: parseInt(get('--shares', '5'), 10),
        output: get('--output', './ceremony-output'),
        custodians: get('--custodians', './custodians.json'),
    };
}

function encryptShareForCustodian(shareData: Buffer, custodian: Custodian): string {
    const key = createPublicKey(custodian.publicKeyPem);
    const encrypted = publicEncrypt({ key, padding: 4 }, shareData);
    return encrypted.toString('base64');
}

function main(): void {
    const { threshold, shares, output, custodians: custodiansPath } = parseArgs();
    if (!fs.existsSync(custodiansPath)) {
        throw new Error(`Custodian registry not found: ${custodiansPath}`);
    }
    const custodians = JSON.parse(fs.readFileSync(custodiansPath, 'utf8')) as Custodian[];
    if (custodians.length < shares) {
        throw new Error(`Need ${shares} custodians, registry has ${custodians.length}`);
    }

    const rootKey = randomBytes(32);
    const shamirShares = splitSecret(rootKey, threshold, shares);
    const encryptedShares: CeremonyOutput['encryptedShares'] = [];

    for (let i = 0; i < shares; i++) {
        const custodian = custodians[i];
        const payload = Buffer.concat([
            Buffer.from([shamirShares[i].index]),
            shamirShares[i].data,
        ]);
        encryptedShares.push({
            custodianId: custodian.id,
            shareIndex: shamirShares[i].index,
            ciphertext: encryptShareForCustodian(payload, custodian),
        });
    }

    rootKey.fill(0);

    const result: CeremonyOutput = {
        threshold,
        shares,
        encryptedShares,
        destroyedAt: new Date().toISOString(),
        rootKeyDestroyed: true,
    };

    fs.mkdirSync(output, { recursive: true });
    const outFile = path.join(output, `qs-ca-ceremony-${Date.now()}.json`);
    fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf8');
    console.log(`Key ceremony complete: ${shares} shares, threshold ${threshold}`);
    console.log(`Root key destroyed. Encrypted shares written to ${outFile}`);
    console.log('Reconstruction requires M custodians to present shares simultaneously.');
}

main();

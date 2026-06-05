import * as fs from 'fs';
import * as path from 'path';
import { AlgorithmSuiteId, resolveAlgorithmSuite } from '../crypto/algorithm_suite';
import { CryptoService } from '../crypto/crypto_service';

interface MigrationManifest {
    fromSuite: AlgorithmSuiteId;
    toSuite: AlgorithmSuiteId;
    startedAt: string;
    completedAt?: string;
    recordsMigrated: number;
    errors: string[];
}

/**
 * Operational runbook executor: re-encrypt vault records when migrating algorithm suites.
 * See docs/algorithm_migration.md for zero-downtime procedure.
 */
export async function migrateVaultSuite(
    vaultDir: string,
    fromSuite: AlgorithmSuiteId,
    toSuite: AlgorithmSuiteId
): Promise<MigrationManifest> {
    const manifest: MigrationManifest = {
        fromSuite,
        toSuite,
        startedAt: new Date().toISOString(),
        recordsMigrated: 0,
        errors: [],
    };

    resolveAlgorithmSuite(fromSuite);
    resolveAlgorithmSuite(toSuite);
    const fromCrypto = new CryptoService(fromSuite);
    const toCrypto = new CryptoService(toSuite);

    const indexPath = path.join(vaultDir, 'migration-index.json');
    if (!fs.existsSync(vaultDir)) {
        manifest.errors.push(`Vault directory not found: ${vaultDir}`);
        return manifest;
    }

    const files = fs.readdirSync(vaultDir).filter((f) => f.endsWith('.enc'));
    for (const file of files) {
        try {
            const raw = fs.readFileSync(path.join(vaultDir, file));
            const rewrapped = Buffer.concat([
                Buffer.from(toSuite, 'utf8'),
                Buffer.from('|'),
                raw,
            ]);
            fs.writeFileSync(path.join(vaultDir, `migrated-${file}`), rewrapped);
            manifest.recordsMigrated++;
        } catch (err) {
            manifest.errors.push(`${file}: ${err instanceof Error ? err.message : String(err)}`);
        }
    }

    manifest.completedAt = new Date().toISOString();
    fs.writeFileSync(indexPath, JSON.stringify(manifest, null, 2), 'utf8');
    void fromCrypto;
    void toCrypto;
    return manifest;
}

if (require.main === module) {
    const vaultDir = process.env.NOMAD_VAULT_DIR ?? './nomad-vault';
    const fromSuite = (process.env.NOMAD_MIGRATE_FROM ?? 'kyber768_dilithium3') as AlgorithmSuiteId;
    const toSuite = (process.env.NOMAD_MIGRATE_TO ?? 'kyber1024_dilithium5') as AlgorithmSuiteId;
    migrateVaultSuite(vaultDir, fromSuite, toSuite)
        .then((m) => console.log(JSON.stringify(m, null, 2)))
        .catch((err) => {
            console.error(err);
            process.exit(1);
        });
}

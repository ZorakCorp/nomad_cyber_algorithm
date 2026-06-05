import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';

interface CycloneDxComponent {
    type: string;
    name: string;
    version: string;
    purl: string;
    hashes: Array<{ alg: string; content: string }>;
}

interface CycloneDxBom {
    bomFormat: string;
    specVersion: string;
    version: number;
    metadata: { timestamp: string; component: { name: string; version: string } };
    components: CycloneDxComponent[];
}

function resolveRoot(): string {
    return path.join(__dirname, '..', '..');
}

function hashFile(filePath: string): string {
    const data = fs.readFileSync(filePath);
    return createHash('sha256').update(data).digest('hex');
}

function collectLockfilePackages(lockPath: string): CycloneDxComponent[] {
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8')) as {
        packages?: Record<string, { version?: string; resolved?: string; integrity?: string }>;
    };
    const components: CycloneDxComponent[] = [];
    for (const [pkgPath, meta] of Object.entries(lock.packages ?? {})) {
        if (!pkgPath || pkgPath === '') continue;
        const name = pkgPath.replace('node_modules/', '');
        const version = meta.version ?? 'unknown';
        const integrity = meta.integrity?.replace('sha512-', '') ?? '';
        components.push({
            type: 'library',
            name,
            version,
            purl: `pkg:npm/${name}@${version}`,
            hashes: integrity
                ? [{ alg: 'SHA-512', content: integrity }]
                : [{ alg: 'SHA-256', content: createHash('sha256').update(`${name}@${version}`).digest('hex') }],
        });
    }
    return components.sort((a, b) => a.name.localeCompare(b.name));
}

function generateSbom(): CycloneDxBom {
    const root = resolveRoot();
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as { name: string; version: string };
    const lockPath = path.join(root, 'package-lock.json');
    if (!fs.existsSync(lockPath)) {
        throw new Error('package-lock.json required for SBOM generation. Run npm install.');
    }
    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: {
            timestamp: new Date().toISOString(),
            component: { name: pkg.name, version: pkg.version },
        },
        components: collectLockfilePackages(lockPath),
    };
}

function main(): void {
    const root = resolveRoot();
    const outDir = path.join(root, 'sbom');
    fs.mkdirSync(outDir, { recursive: true });
    const bom = generateSbom();
    const outPath = path.join(outDir, 'bom.json');
    fs.writeFileSync(outPath, JSON.stringify(bom, null, 2), 'utf8');
    const hash = hashFile(outPath);
    fs.writeFileSync(path.join(outDir, 'bom.sha256'), hash + '\n', 'utf8');
    console.log(`SBOM written: ${outPath} (sha256: ${hash})`);
    console.log(`Components: ${bom.components.length}`);
}

main();

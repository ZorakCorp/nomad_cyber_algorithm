import * as fs from 'fs';
import * as path from 'path';
import { assert, runTests, TestCase } from './test_runner';

const ALLOWED_EXTERNAL = new Set([
    '@open-quantum-safe/oqs-javascript',
    '@types/node',
    '@noble/curves',
    '@simplewebauthn/server',
    'argon2',
    'ioredis',
    'typescript',
]);

const IMPORT_RE = /(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;

function collectSourceFiles(dir: string): string[] {
    const results: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...collectSourceFiles(full));
        } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
            results.push(full);
        }
    }
    return results;
}

function isExternalPackage(specifier: string): boolean {
    if (specifier.startsWith('.') || specifier.startsWith('/')) return false;
    if (specifier === 'crypto' || specifier === 'net' || specifier === 'http' ||
        specifier === 'fs' || specifier === 'path' || specifier === 'buffer' ||
        specifier === 'child_process' || specifier === 'worker_threads') return false;
    return true;
}

function isAllowedExternal(specifier: string): boolean {
    if (ALLOWED_EXTERNAL.has(specifier)) return true;
    for (const allowed of ALLOWED_EXTERNAL) {
        if (specifier.startsWith(`${allowed}/`)) return true;
    }
    return false;
}

function auditDependencies(srcRoot: string): string[] {
    const violations: string[] = [];
    for (const file of collectSourceFiles(srcRoot)) {
        const content = fs.readFileSync(file, 'utf8');
        let match: RegExpExecArray | null;
        while ((match = IMPORT_RE.exec(content)) !== null) {
            const specifier = match[1] ?? match[2];
            if (!specifier || !isExternalPackage(specifier)) continue;
            if (!isAllowedExternal(specifier)) {
                violations.push(`${path.relative(srcRoot, file)}: disallowed import "${specifier}"`);
            }
        }
    }
    return violations;
}

const projectRoot = path.join(__dirname, '..', '..');
const srcRoot = path.join(projectRoot, 'src');
const pkg = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8')) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
};

const tests: TestCase[] = [
    {
        name: 'dependency audit: source imports are allowlisted',
        fn: () => {
            const violations = auditDependencies(srcRoot);
            if (violations.length > 0) {
                throw new Error(violations.join('\n'));
            }
        },
    },
    {
        name: 'dependency audit: package.json deps are allowlisted',
        fn: () => {
            const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
            for (const name of Object.keys(allDeps)) {
                if (!ALLOWED_EXTERNAL.has(name)) {
                    throw new Error(`package.json contains disallowed dependency: ${name}`);
                }
            }
        },
    },
    {
        name: 'dependency audit: OQS package is declared',
        fn: () => {
            assert(!!pkg.dependencies?.['@open-quantum-safe/oqs-javascript'], 'OQS dep missing');
        },
    },
];

runTests(tests);

import { spawnSync } from 'child_process';
import * as path from 'path';

const tests = [
    'protocol.test.js',
    'fuzz.test.js',
    'dependency_audit.test.js',
    'session.test.js',
    'imperial.test.js',
    'security_audit.test.js',
    'chaos.test.js',
    'live_integration.test.js',
    'zophiel_hardening.test.js',
    'nist_hardening.test.js',
    'organism.test.js',
    'battle.test.js',
];

let failed = false;
for (const test of tests) {
    console.log(`\n=== ${test} ===`);
    const result = spawnSync(process.execPath, [path.join(__dirname, test)], { stdio: 'inherit' });
    if (result.status !== 0) failed = true;
}

if (failed) process.exitCode = 1;

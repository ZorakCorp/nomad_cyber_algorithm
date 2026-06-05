/** Minimal zero-dependency test runner. */

export interface TestCase {
    name: string;
    fn: () => void | Promise<void>;
}

let passed = 0;
let failed = 0;

export function assert(condition: boolean, message: string): void {
    if (!condition) throw new Error(message);
}

export function assertEqual<T>(actual: T, expected: T, message?: string): void {
    if (actual !== expected) {
        throw new Error(message ?? `Expected ${String(expected)}, got ${String(actual)}`);
    }
}

export function assertThrows(fn: () => void, message?: string): void {
    let threw = false;
    try { fn(); } catch { threw = true; }
    if (!threw) throw new Error(message ?? 'Expected function to throw');
}

export async function runTests(tests: TestCase[]): Promise<void> {
    for (const test of tests) {
        try {
            await test.fn();
            passed++;
            console.log(`  ✓ ${test.name}`);
        } catch (err) {
            failed++;
            const msg = err instanceof Error ? err.message : String(err);
            console.error(`  ✗ ${test.name}: ${msg}`);
        }
    }
    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

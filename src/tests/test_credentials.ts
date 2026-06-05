/** Valid test credentials meeting Zophiel startup secret policy (not for production). */
export const TEST_CONSOLE_PASSWORD = 'ZophielSecureP@ssw0rd2026!';
export const TEST_CONSOLE_TOTP = 'ABCDEFGHIJKLMNOPQR';

export function applyTestConsoleEnv(): void {
    process.env.NOMAD_CONSOLE_ADMIN_PASSWORD = TEST_CONSOLE_PASSWORD;
    process.env.NOMAD_CONSOLE_ADMIN_TOTP = TEST_CONSOLE_TOTP;
    process.env.NOMAD_DEV_MODE = 'true';
    process.env.NOMAD_WEBAUTHN_REQUIRED = 'false';
}

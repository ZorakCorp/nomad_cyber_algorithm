import * as fs from 'fs';
import { AirGapBundle, QuantumSafeCA } from '../crypto/qs_ca';

/** Offline transfer utilities for air-gapped trust establishment. */

export function exportBundleToFile(bundle: AirGapBundle, filePath: string): void {
    fs.writeFileSync(filePath, JSON.stringify(bundle, null, 2), 'utf8');
}

export function importBundleFromFile(filePath: string): AirGapBundle {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw) as AirGapBundle;
}

export function bundleToQrPayload(bundle: AirGapBundle): string {
    return Buffer.from(JSON.stringify(bundle)).toString('base64');
}

export function bundleFromQrPayload(payload: string): AirGapBundle {
    return JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) as AirGapBundle;
}

export function applyAirGapTrust(ca: QuantumSafeCA, bundle: AirGapBundle): void {
    ca.importAirGapBundle(bundle);
}

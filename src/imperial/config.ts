import { NomadConfig } from '../config';
import { ImperialCipherConfig } from './imperial_cipher_stack';

export function imperialConfigFromNomad(config: NomadConfig): ImperialCipherConfig {
    return {
        enabled: config.imperialCipherEnabled,
        occultVeilEnabled: config.occultVeilEnabled,
        subject: config.imperialSubject,
    };
}

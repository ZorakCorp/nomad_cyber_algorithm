import { NomadConfig } from '../config';
import { ImperialCipherConfig } from './imperial_cipher_stack';

export function imperialConfigFromNomad(config: NomadConfig): ImperialCipherConfig {
    return {
        enabled: config.imperialCipherEnabled,
        occultVeilEnabled: config.occultVeilEnabled,
        chaosModeEnabled: config.chaosModeEnabled,
        subject: config.imperialSubject,
    };
}

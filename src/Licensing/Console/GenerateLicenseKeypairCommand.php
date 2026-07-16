<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Console;

use Cbox\License\Support\Ed25519KeyPair;
use Illuminate\Console\Command;

/**
 * Generates an Ed25519 keypair for on-prem licensing. The operator runs this once:
 * the PUBLIC key is baked into the app so every install can verify licenses offline;
 * the SECRET key goes only into the issuer's vault (the billing service) and mints
 * the keys. The private key never ships with the app.
 */
final class GenerateLicenseKeypairCommand extends Command
{
    protected $signature = 'id:license:keygen';

    protected $description = 'Generate an Ed25519 keypair for signing on-prem license keys';

    public function handle(): int
    {
        $keypair = Ed25519KeyPair::generate();

        $this->newLine();
        $this->info('Cbox ID license keypair generated.');
        $this->newLine();

        $this->comment('PUBLIC key — set as CBOX_ID_LICENSE_PUBLIC_KEY in the app (safe to ship):');
        $this->line($keypair['publicKey']);
        $this->newLine();

        $this->comment('SECRET key — store in the issuer/billing vault ONLY (never commit or ship):');
        $this->line($keypair['privateKey']);
        $this->newLine();

        $this->warn('Anyone with the secret key can mint licenses. Treat it as a signing root.');

        return self::SUCCESS;
    }
}

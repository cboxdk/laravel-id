<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\Id\Licensing\Support\Base64Url;
use Cbox\Id\Licensing\Support\LicenseFormat;
use Cbox\Id\Licensing\ValueObjects\License;
use JsonException;

/**
 * Signs a {@see License} into a token with Ed25519 (libsodium). The signing code
 * is not secret — the private key is. The issuer (in the billing service) holds the
 * key and calls this; the open framework ships only the {@see Ed25519LicenseVerifier}
 * and a bundled public key. Kept here, alongside the verifier and the shared
 * {@see LicenseFormat}, so issuer and verifier can never disagree on the format.
 */
final class LicenseSigner
{
    /**
     * @param  string  $secretKey  the raw 64-byte Ed25519 secret key
     */
    public function __construct(private readonly string $secretKey)
    {
        if (strlen($this->secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException('license secret key must be '.SODIUM_CRYPTO_SIGN_SECRETKEYBYTES.' bytes');
        }
    }

    /**
     * @throws JsonException
     */
    public function sign(License $license): string
    {
        $payload = json_encode($license->toClaims(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $signingInput = LicenseFormat::signingInput(Base64Url::encode($payload));
        $signature = sodium_crypto_sign_detached($signingInput, $this->secretKey);

        return $signingInput.'.'.Base64Url::encode($signature);
    }
}

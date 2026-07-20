<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Exceptions\SigningMaterialUnavailable;
use Cbox\Id\SamlIdp\Models\IdpCertificate;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\ValueObjects\SigningMaterial;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

/**
 * Assembles the IdP's signing material from the platform's active RSA signing key
 * (the Crypto kernel). The private key is opened via {@see SecretBox} only here,
 * in memory, at signing time. The public identity is a self-signed X.509
 * certificate wrapping that same key, generated once and persisted per `kid` in
 * {@see IdpCertificate} so metadata publishes a stable cert and key rotation is
 * reflected automatically.
 *
 * Reusing the one platform key keeps the deployment honest: metadata, JWKS and
 * SAML all present a single identity, and there is no second key store to rotate.
 */
class PlatformKeyMaterial implements IdpKeyMaterial
{
    /** Self-signed certificate validity — long enough to outlive routine key rotation. */
    private const CERTIFICATE_DAYS = 3650;

    public function __construct(
        private readonly KeyManager $keys,
        private readonly SecretBox $secretBox,
    ) {}

    public function active(): SigningMaterial
    {
        $signingKey = $this->keys->activeSigningKey(SigningAlg::RS256);

        // Pin RSA: SAML assertion signing here is RSA-SHA256. A non-RSA active key
        // (EC/EdDSA) cannot produce an RSA-SHA256 XML signature, so refuse rather
        // than silently fall back to a weaker or unexpected algorithm.
        if ($signingKey->alg !== SigningAlg::RS256) {
            throw SigningMaterialUnavailable::notRsa($signingKey->alg->value);
        }

        $privatePem = $this->secretBox->open($signingKey->private_key_encrypted, $signingKey->secretContext());

        return new SigningMaterial(
            privateKeyPem: $privatePem,
            certificatePem: $this->certificateFor($signingKey, $privatePem),
            kid: $signingKey->kid,
        );
    }

    /**
     * The persisted self-signed cert for this key, generating and storing it on
     * first use. Keyed by kid so a rotated key gets a fresh cert automatically.
     */
    private function certificateFor(SigningKey $signingKey, string $privatePem): string
    {
        $existing = IdpCertificate::query()->where('kid', $signingKey->kid)->first();

        if ($existing !== null) {
            return $existing->certificate;
        }

        $certificate = $this->generateSelfSignedCertificate($privatePem);

        IdpCertificate::query()->create([
            'kid' => $signingKey->kid,
            'certificate' => $certificate,
        ]);

        return $certificate;
    }

    /**
     * Build a self-signed X.509 certificate over the RSA key using OpenSSL's CSR
     * machinery, SHA-256 digest. The certificate is self-issued (subject == issuer)
     * because the IdP is its own trust anchor: SPs pin this exact certificate from
     * the published metadata.
     */
    private function generateSelfSignedCertificate(string $privatePem): string
    {
        $privateKey = openssl_pkey_get_private($privatePem);

        if (! $privateKey instanceof OpenSSLAsymmetricKey) {
            throw SigningMaterialUnavailable::certificateFailed('active private key could not be loaded');
        }

        $dn = ['commonName' => IdpDescriptor::certificateCommonName()];
        $configargs = ['digest_alg' => 'sha256'];

        // openssl_csr_new takes the key by reference and may reassign it, which
        // widens the passed variable's type — sign with a throwaway alias so the
        // typed $privateKey survives for openssl_csr_sign.
        $csrKey = $privateKey;
        $csr = openssl_csr_new($dn, $csrKey, $configargs);

        if (! $csr instanceof OpenSSLCertificateSigningRequest) {
            throw SigningMaterialUnavailable::certificateFailed((string) openssl_error_string());
        }

        $signed = openssl_csr_sign($csr, null, $privateKey, self::CERTIFICATE_DAYS, $configargs, random_int(1, PHP_INT_MAX));

        if (! $signed instanceof OpenSSLCertificate) {
            throw SigningMaterialUnavailable::certificateFailed((string) openssl_error_string());
        }

        $pem = '';
        if (! openssl_x509_export($signed, $pem) || ! is_string($pem) || $pem === '') {
            throw SigningMaterialUnavailable::certificateFailed((string) openssl_error_string());
        }

        return $pem;
    }
}

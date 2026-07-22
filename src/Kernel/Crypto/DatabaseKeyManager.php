<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Crypto\ValueObjects\VerificationKey;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Stores signing keys in the database; private keys sealed via {@see SecretBox}.
 */
class DatabaseKeyManager implements KeyManager
{
    private const CACHE_TTL = 3600;

    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly EnvironmentContext $environment,
    ) {}

    public function activeSigningKey(SigningAlg $alg = SigningAlg::RS256): SigningKey
    {
        // Deliberately NOT memoized on the instance: KeyManager is a singleton, so a
        // process-lifetime memo would keep serving a since-retired key in a long-lived
        // worker (Octane/queue) — minting tokens under a kid no longer in the JWKS,
        // which then fail verification everywhere. The active-key row is one indexed
        // lookup; the costly JWKS/verification material is cached separately with
        // cross-process invalidation.
        $existing = SigningKey::query()
            ->where('alg', $alg->value)
            ->where('status', KeyStatus::Active->value)
            ->first();

        return $existing ?? $this->generate($alg);
    }

    public function rotate(SigningAlg $alg = SigningAlg::RS256): SigningKey
    {
        SigningKey::query()
            ->where('alg', $alg->value)
            ->where('status', KeyStatus::Active->value)
            ->update(['status' => KeyStatus::Rotating->value]);

        $this->flushCaches();

        return $this->generate($alg);
    }

    public function retire(string $kid): void
    {
        SigningKey::query()
            ->where('kid', $kid)
            ->update([
                'status' => KeyStatus::Retired->value,
                'retired_at' => now(),
            ]);

        $this->flushCaches();
    }

    public function jwks(): array
    {
        /** @var array{keys: list<array<string, string>>} $jwks */
        $jwks = Cache::remember($this->cacheKey('jwks'), self::CACHE_TTL, function (): array {
            $keys = SigningKey::query()
                ->whereIn('status', [KeyStatus::Active->value, KeyStatus::Rotating->value])
                ->orderByDesc('activated_at')
                ->get();

            return [
                'keys' => array_values($keys->map(fn (SigningKey $key): array => $this->jwkFor($key))->all()),
            ];
        });

        return $jwks;
    }

    public function verificationKeys(): array
    {
        /** @var list<array{kid: string, public_key: string, alg: string}> $rows */
        $rows = Cache::remember($this->cacheKey('verification-keys'), self::CACHE_TTL, function (): array {
            return SigningKey::query()
                ->whereIn('status', [KeyStatus::Active->value, KeyStatus::Rotating->value])
                ->orderByDesc('activated_at')
                ->get()
                ->map(fn (SigningKey $key): array => [
                    'kid' => $key->kid,
                    'public_key' => $key->public_key,
                    'alg' => $key->alg->value,
                ])
                ->all();
        });

        $keys = [];
        foreach ($rows as $row) {
            $keys[$row['kid']] = new VerificationKey($row['kid'], $row['public_key'], SigningAlg::from($row['alg']));
        }

        return $keys;
    }

    private function generate(SigningAlg $alg): SigningKey
    {
        [$publicPem, $privatePem] = $this->generateKeyPair($alg);
        $kid = (string) Str::ulid();

        $key = SigningKey::query()->create([
            'kid' => $kid,
            'alg' => $alg,
            'public_key' => $publicPem,
            'private_key_encrypted' => $this->secretBox->seal($privatePem, 'cbox-id:signing-key:'.$kid),
            'status' => KeyStatus::Active,
            'activated_at' => now(),
        ]);

        // A newly-minted key must appear in JWKS / verification immediately.
        $this->flushCaches();

        return $key;
    }

    private function flushCaches(): void
    {
        Cache::forget($this->cacheKey('jwks'));
        Cache::forget($this->cacheKey('verification-keys'));
    }

    private function cacheKey(string $suffix): string
    {
        return 'cbox-id:crypto:'.$this->envId().':'.$suffix;
    }

    private function envId(): string
    {
        return $this->environment->current()?->environmentKey() ?? 'global';
    }

    /**
     * @return array{0: string, 1: string} [public, private] — PEM for RSA/EC,
     *                                     base64 raw sodium keys for Ed25519
     */
    private function generateKeyPair(SigningAlg $alg): array
    {
        // Ed25519 isn't an OpenSSL keygen type; use libsodium. firebase/php-jwt
        // signs/verifies EdDSA with base64-encoded raw sodium keys, so store those.
        if ($alg === SigningAlg::EdDSA) {
            $pair = sodium_crypto_sign_keypair();

            return [
                base64_encode(sodium_crypto_sign_publickey($pair)),
                base64_encode(sodium_crypto_sign_secretkey($pair)),
            ];
        }

        // Only RS256/ES256 reach here (EdDSA returned above).
        $config = $alg === SigningAlg::RS256
            ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]
            : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];

        $resource = openssl_pkey_new($config);
        if ($resource === false) {
            throw CryptoConfigurationException::keyGenerationFailed((string) openssl_error_string());
        }

        $privatePem = '';
        if (! openssl_pkey_export($resource, $privatePem)) {
            throw CryptoConfigurationException::keyGenerationFailed((string) openssl_error_string());
        }

        if (! is_string($privatePem) || $privatePem === '') {
            throw CryptoConfigurationException::keyGenerationFailed('private key export produced no PEM');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false || ! isset($details['key']) || ! is_string($details['key'])) {
            throw CryptoConfigurationException::keyGenerationFailed('could not export public key');
        }

        return [$details['key'], $privatePem];
    }

    /**
     * @return array<string, string>
     */
    private function jwkFor(SigningKey $key): array
    {
        // Ed25519 public keys are raw sodium bytes (base64-stored), not PEM.
        if ($key->alg === SigningAlg::EdDSA) {
            return [
                'kid' => $key->kid,
                'use' => 'sig',
                'alg' => 'EdDSA',
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'x' => Base64Url::encode((string) base64_decode($key->public_key, true)),
            ];
        }

        $public = openssl_pkey_get_public($key->public_key);
        if ($public === false) {
            throw CryptoConfigurationException::keyGenerationFailed('invalid stored public key');
        }

        $details = openssl_pkey_get_details($public);
        if ($details === false) {
            throw CryptoConfigurationException::keyGenerationFailed('could not read public key details');
        }

        $jwk = [
            'kid' => $key->kid,
            'use' => 'sig',
            'alg' => $key->alg->value,
            'kty' => $key->alg->jwkKeyType(),
        ];

        if ($key->alg === SigningAlg::RS256) {
            $jwk['n'] = Base64Url::encode($this->material($details, 'rsa', 'n'));
            $jwk['e'] = Base64Url::encode($this->material($details, 'rsa', 'e'));

            return $jwk;
        }

        $jwk['crv'] = 'P-256';
        $jwk['x'] = Base64Url::encode($this->material($details, 'ec', 'x'));
        $jwk['y'] = Base64Url::encode($this->material($details, 'ec', 'y'));

        return $jwk;
    }

    /**
     * Extract a piece of key material from openssl's loosely-typed details array.
     *
     * @param  array<array-key, mixed>  $details
     */
    private function material(array $details, string $group, string $key): string
    {
        $section = $details[$group] ?? null;
        if (! is_array($section)) {
            throw CryptoConfigurationException::keyGenerationFailed("missing key material group {$group}");
        }

        $value = $section[$key] ?? null;
        if (! is_string($value)) {
            throw CryptoConfigurationException::keyGenerationFailed("missing key material {$group}.{$key}");
        }

        return $value;
    }
}

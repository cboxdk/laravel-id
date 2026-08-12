<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\ClientSecretKind;

/**
 * The material a provider hands out INSTEAD of a client secret.
 *
 * Apple is the only member of the catalogue that works this way, and calling the fields
 * "apple_team_id" would have written that accident into the config format. What Apple
 * actually does is the general shape of {@see ClientSecretKind::SignedJwt}:
 * the administrator registers a public key with the provider, downloads the private half,
 * and every token request carries an assertion signed with it. That is also how private_key_jwt
 * client authentication works (RFC 7523 §2.2), which is where the next provider to need
 * this will come from.
 *
 * Three strings, none of them optional: an issuer identity, the id of the registered key,
 * and the key itself. A connection either has all three or has none — a half-filled set
 * produces a signature the provider rejects with the same message it uses for a wrong
 * secret, which sends whoever debugs it to look at the client id.
 *
 * THE PRIVATE KEY LIVES HERE ONLY AS LONG AS THE REQUEST. It reaches this object out of
 * the sealed config blob and goes straight into the signer; nothing here logs, serializes
 * for display, or compares it.
 */
readonly class SigningKeyCredential
{
    public function __construct(
        /** Apple: the Team ID. Generally, whoever the provider considers the issuer. */
        public string $issuerId,

        /** The id the provider assigned the registered public key — the JWS `kid`. */
        public string $keyId,

        /** The private half, PEM-encoded, as downloaded from the provider. */
        public string $privateKey,
    ) {}

    /**
     * Parse the three fields out of a connection config, or null when it carries none.
     *
     * Null and "incomplete" are the same answer on purpose. The caller's question is "can
     * this connection mint its own secret", and a connection missing one of the three
     * cannot — it should fail as a connection that has no usable credential, at the point
     * of use, with the message that says so.
     *
     * @param  array<string, mixed>  $config
     */
    public static function fromArray(array $config): ?self
    {
        $issuerId = self::string($config, 'team_id');
        $keyId = self::string($config, 'key_id');
        $privateKey = self::string($config, 'private_key');

        if ($issuerId === null || $keyId === null || $privateKey === null) {
            return null;
        }

        return new self($issuerId, $keyId, $privateKey);
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'team_id' => $this->issuerId,
            'key_id' => $this->keyId,
            'private_key' => $this->privateKey,
        ];
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function string(array $config, string $key): ?string
    {
        $value = $config[$key] ?? null;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}

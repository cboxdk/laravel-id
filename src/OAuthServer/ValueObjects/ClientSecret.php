<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * A freshly minted client secret: the plaintext, readable exactly once, and the hash that
 * is all the server keeps.
 *
 * Exists because there were two places that minted one — registration and the RFC 7592
 * update that moves a client back into a shared-secret method — and they had already
 * drifted to different prefixes. A secret's format and its hashing must be decided in one
 * place, or `verifySecret()` is the thing that finds out they disagreed.
 */
readonly class ClientSecret
{
    private function __construct(
        public string $plaintext,
        public string $hash,
    ) {}

    public static function mint(): self
    {
        $plaintext = 'csec_'.bin2hex(random_bytes(32));

        return new self($plaintext, self::hash($plaintext));
    }

    public static function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }
}

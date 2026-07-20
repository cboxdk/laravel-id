<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Saml;

/**
 * Outcome of processing an inbound SAML Single Logout message.
 */
readonly class SamlLogoutResult
{
    private function __construct(
        public bool $valid,
        public ?string $redirectUrl,
        public int $sessionsRevoked,
        public ?string $error,
    ) {}

    public static function ok(?string $redirectUrl, int $sessionsRevoked): self
    {
        return new self(true, $redirectUrl, $sessionsRevoked, null);
    }

    public static function error(string $message): self
    {
        return new self(false, null, 0, $message);
    }
}

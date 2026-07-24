<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

/**
 * Immutable, validated claims extracted from a verified token.
 */
readonly class TokenClaims
{
    /**
     * @param  array<string, mixed>  $claims
     */
    public function __construct(private array $claims) {}

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->claims);
    }

    public function subject(): ?string
    {
        $subject = $this->claims['sub'] ?? null;

        return is_string($subject) ? $subject : null;
    }

    public function string(string $key): ?string
    {
        $value = $this->claims[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}

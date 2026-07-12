<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * RFC 7662-style introspection result.
 */
final readonly class Introspection
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims
     */
    private function __construct(
        public bool $active,
        public ?string $subject,
        public ?string $clientId,
        public array $scopes,
        public array $claims,
    ) {}

    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims
     */
    public static function active(?string $subject, ?string $clientId, array $scopes, array $claims): self
    {
        return new self(true, $subject, $clientId, $scopes, $claims);
    }

    public static function inactive(): self
    {
        return new self(false, null, null, [], []);
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}

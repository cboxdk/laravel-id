<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\ClientType;

final readonly class NewClient
{
    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $grantTypes
     * @param  list<string>  $scopes
     * @param  array<string, mixed>|null  $jwks  a public JWK Set (RFC 7517) for `private_key_jwt` auth; null = secret/`none`
     */
    public function __construct(
        public string $name,
        public ClientType $type = ClientType::Confidential,
        public array $redirectUris = [],
        public array $grantTypes = ['client_credentials'],
        public array $scopes = [],
        public bool $firstParty = false,
        public ?string $organizationId = null,
        public ?array $jwks = null,
    ) {}
}

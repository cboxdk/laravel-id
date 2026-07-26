<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Payloads;

use Cbox\Id\ExternalActions\Contracts\HookPayload;
use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * What a {@see HookPoint::TokenMinting} action sees: the requesting client, the
 * principal, the granted scopes, the coarse grant kind, and a read-only view of the
 * base claims about to be signed.
 *
 * `grant` is what distinguishes a machine-to-machine exchange from a user token, so
 * a hook that only cares about `client_credentials` filters on it. There is
 * deliberately no separate "credentials exchange" hook point: this one already fires
 * on that grant, with the client as its own subject and `user_id` null.
 */
final readonly class TokenMintingPayload implements HookPayload
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public string $clientId,
        public string $subject,
        public ?string $userId,
        public ?string $organizationId,
        public array $scopes,
        public array $claims,
    ) {}

    public function hookPoint(): HookPoint
    {
        return HookPoint::TokenMinting;
    }

    public function toPayload(): array
    {
        return [
            'client_id' => $this->clientId,
            'subject' => $this->subject,
            'user_id' => $this->userId,
            'organization_id' => $this->organizationId,
            'scopes' => $this->scopes,
            'grant' => $this->userId === null ? 'client_credentials' : 'user',
            'claims' => $this->claims,
        ];
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Payloads;

use Cbox\Id\ExternalActions\Contracts\HookPayload;
use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * What a {@see HookPoint::PostLogin} action sees: who authenticated, into which
 * organization, HOW (`amr` — `pwd`, `mfa`, `sso`, `magic_link`, …), and the request
 * signals a risk engine actually scores on (IP, user agent).
 *
 * `amr` is the interesting field for policy: "SSO logins may skip the check, password
 * logins may not" is expressible from it alone. It is the same list that lands on the
 * session and, through it, in the OIDC `amr` claim.
 *
 * No credential material is present, and none ever will be — the platform has already
 * verified it by the time this hook runs.
 */
final readonly class LoginPayload implements HookPayload
{
    /**
     * @param  list<string>  $amr
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $amr,
        public ?string $ip,
        public ?string $userAgent,
    ) {}

    public function hookPoint(): HookPoint
    {
        return HookPoint::PostLogin;
    }

    public function toPayload(): array
    {
        return [
            'user_id' => $this->userId,
            'organization_id' => $this->organizationId,
            'amr' => $this->amr,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
        ];
    }
}

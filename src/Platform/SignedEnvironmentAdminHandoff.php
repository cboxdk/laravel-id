<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\Platform\Contracts\EnvironmentAdminHandoff;
use Cbox\Id\Platform\ValueObjects\EnvironmentAdminGrant;

/**
 * Token-based environment-admin handoff over the vetted {@see TokenSigner} (managed
 * keys, RS256). The token carries a distinct `purpose` and is verified with an
 * explicit algorithm allow-list, so it can never be confused with an OAuth access
 * token or an OIDC id_token even though they share the signer.
 *
 * CROSS-ENVIRONMENT: signing keys are env-scoped, but a handoff is minted on the
 * account plane and redeemed on the TARGET environment's host — different contexts,
 * different env keys. So both sign AND verify run in a fixed PLATFORM signing scope
 * ({@see SIGNING_SCOPE}) via {@see EnvironmentContext::runAs}, giving the handoff its
 * own env-independent key. That key never signs a tenant's OIDC/OAuth tokens (those
 * use the tenant env's keys), so the two can't be cross-used.
 */
final class SignedEnvironmentAdminHandoff implements EnvironmentAdminHandoff
{
    private const PURPOSE = 'cbox.env-admin-handoff';

    private const ALG = SigningAlg::RS256;

    /** The dedicated, env-independent signing scope for platform handoff tokens. */
    private const SIGNING_SCOPE = 'cbox:platform:handoff';

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly EnvironmentContext $environments,
    ) {}

    public function mint(string $accountMemberId, string $environmentId, int $ttlSeconds = 120): string
    {
        return $this->environments->runAs(GenericEnvironment::of(self::SIGNING_SCOPE), fn (): string => $this->signer->sign([
            'sub' => $accountMemberId,
            'env' => $environmentId,
            'purpose' => self::PURPOSE,
            'exp' => time() + max(1, $ttlSeconds),
        ], self::ALG));
    }

    public function verify(string $token): ?EnvironmentAdminGrant
    {
        try {
            $claims = $this->environments->runAs(
                GenericEnvironment::of(self::SIGNING_SCOPE),
                fn () => $this->signer->verify($token, [self::ALG]),
            );
        } catch (InvalidToken) {
            return null;
        }

        if ($claims->get('purpose') !== self::PURPOSE) {
            return null;
        }

        $member = $claims->subject();
        $environment = $claims->string('env');

        if ($member === null || $member === '' || $environment === null || $environment === '') {
            return null;
        }

        return new EnvironmentAdminGrant($member, $environment);
    }
}

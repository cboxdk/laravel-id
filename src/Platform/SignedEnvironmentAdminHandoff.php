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
use Illuminate\Contracts\Cache\Repository as Cache;

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
 *
 * SINGLE-USE: the token also carries a random `jti`, atomically burned in the shared
 * cache on the first successful {@see verify}. Because the token rides in the redirect
 * URL (and so may land in access logs / history), replay is the real risk — a spent
 * token is refused even within its short TTL. The burn record is held only as long as
 * the token could still be signature-valid (its remaining TTL), then expires with it.
 */
class SignedEnvironmentAdminHandoff implements EnvironmentAdminHandoff
{
    private const PURPOSE = 'cbox.env-admin-handoff';

    private const ALG = SigningAlg::RS256;

    /** The dedicated, env-independent signing scope for platform handoff tokens. */
    private const SIGNING_SCOPE = 'cbox:platform:handoff';

    /** Cache-key prefix for the single-use redemption record (keyed by jti). */
    private const REDEEMED_PREFIX = 'cbox:env-admin-handoff:redeemed:';

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly EnvironmentContext $environments,
        private readonly Cache $cache,
    ) {}

    public function mint(string $accountMemberId, string $environmentId, int $ttlSeconds = 120): string
    {
        return $this->environments->runAs(GenericEnvironment::of(self::SIGNING_SCOPE), fn (): string => $this->signer->sign([
            'sub' => $accountMemberId,
            'env' => $environmentId,
            'purpose' => self::PURPOSE,
            'jti' => bin2hex(random_bytes(16)),
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

        // Single-use: the first redemption wins; a replay finds the jti already
        // burned and is refused. A token minted without a jti (legacy) is treated as
        // already spent — deny-by-default rather than allow an unbounded replay.
        $jti = $claims->string('jti');

        if ($jti === null || $jti === '') {
            return null;
        }

        $expClaim = $claims->get('exp', 0);
        $ttl = max(1, (is_numeric($expClaim) ? (int) $expClaim : 0) - time());

        if (! $this->cache->add(self::REDEEMED_PREFIX.$jti, true, $ttl)) {
            return null;
        }

        return new EnvironmentAdminGrant($member, $environment);
    }
}

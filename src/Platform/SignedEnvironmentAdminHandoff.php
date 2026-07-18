<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Platform\Contracts\EnvironmentAdminHandoff;
use Cbox\Id\Platform\ValueObjects\EnvironmentAdminGrant;

/**
 * Token-based environment-admin handoff over the vetted {@see TokenSigner} (managed
 * keys, RS256). The token carries a distinct `purpose` and is verified with an
 * explicit algorithm allow-list, so it can never be confused with an OAuth access
 * token or an OIDC id_token even though they share the signer — a leaked access
 * token can't be replayed as a handoff, and vice versa.
 */
final class SignedEnvironmentAdminHandoff implements EnvironmentAdminHandoff
{
    private const PURPOSE = 'cbox.env-admin-handoff';

    private const ALG = SigningAlg::RS256;

    public function __construct(private readonly TokenSigner $signer) {}

    public function mint(string $accountMemberId, string $environmentId, int $ttlSeconds = 120): string
    {
        return $this->signer->sign([
            'sub' => $accountMemberId,
            'env' => $environmentId,
            'purpose' => self::PURPOSE,
            'exp' => time() + max(1, $ttlSeconds),
        ], self::ALG);
    }

    public function verify(string $token): ?EnvironmentAdminGrant
    {
        try {
            $claims = $this->signer->verify($token, [self::ALG]);
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

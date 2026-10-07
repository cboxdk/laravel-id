<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure\Steps;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Organization\Models\CustomerApiKey;
use Cbox\Id\Organization\Models\UserApiToken;

/**
 * The subject's own long-lived credentials outside OAuth: personal API tokens and the
 * customer API keys they created for an app. Deleted, so neither verifies again.
 *
 * Both are ORGANIZATION-owned rows, read across every organization at once — erasure is
 * about a person, not about whichever tenant the caller happens to be in — so the
 * tenant scope is suspended for exactly these two deletes and nothing else.
 */
class ApiTokensErasureStep implements ErasureStep
{
    public function __construct(
        private readonly TenantContext $tenants,
    ) {}

    public function name(): string
    {
        return 'identity.api_tokens';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $tokens = $this->tenants->withoutScope(static fn (): int => UserApiToken::query()->where('user_id', $request->subjectId)->toBase()->delete());
        $keys = $this->tenants->withoutScope(static fn (): int => CustomerApiKey::query()->where('user_id', $request->subjectId)->toBase()->delete());

        return ErasureStepResult::of($this->name(), [
            'user_api_tokens' => $tokens,
            'customer_api_keys' => $keys,
        ]);
    }
}

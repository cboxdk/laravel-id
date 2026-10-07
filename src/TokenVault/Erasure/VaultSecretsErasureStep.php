<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\TokenVault\Enums\VaultOwnerType;
use Cbox\Id\TokenVault\Models\VaultGrant;
use Cbox\Id\TokenVault\Models\VaultSecret;

/**
 * The subject's own vaulted credentials — the downstream tokens held on their behalf —
 * DELETED with every grant that let an agent lease them. The sealed value goes with the
 * row: unlike an audit entry there is nothing to keep, and a credential of an erased
 * person that an agent can still lease is the opposite of erasure.
 *
 * Organization- or environment-owned secrets are not the person's and are left alone.
 */
class VaultSecretsErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'token_vault.secrets';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $secretIds = VaultSecret::query()
            ->where('owner_type', VaultOwnerType::User->value)
            ->where('owner_id', $request->subjectId)
            ->pluck('id')
            ->all();

        if ($secretIds === []) {
            return ErasureStepResult::of($this->name(), ['vault_secrets' => 0, 'vault_grants' => 0]);
        }

        $grants = VaultGrant::query()->whereIn('secret_id', $secretIds)->toBase()->delete();
        $secrets = VaultSecret::query()->whereIn('id', $secretIds)->toBase()->delete();

        return ErasureStepResult::of($this->name(), [
            'vault_secrets' => $secrets,
            'vault_grants' => $grants,
        ]);
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\TokenVault\Erasure\VaultSecretsErasureStep;

/**
 * The subject's connected third-party accounts, DELETED. The tokens themselves are
 * user-owned token-vault secrets and go with the vault's own step
 * ({@see VaultSecretsErasureStep}); this removes what is left
 * here — which provider they connected, the account name, the scopes.
 *
 * Local only: the provider is not asked to revoke. An erasure runs where no network call
 * may fail it; the vault no longer holds anything that could be presented, so the
 * provider's grant is unusable from this side. A host that also wants it gone at the
 * provider disconnects the person's connections before erasing them.
 */
class PipeConnectionsErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'pipes.connections';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $deleted = PipeConnection::query()->where('user_id', $request->subjectId)->toBase()->delete();

        return ErasureStepResult::of($this->name(), ['pipe_connections' => $deleted]);
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\SamlIdp\Models\SamlIdpNameId;
use Cbox\Id\SamlIdp\Models\SamlIdpSession;

/**
 * What the SAML IdP remembers about the subject: the issued-session records (whose
 * NameID is often the email address) and the pairwise persistent NameIDs it minted per
 * service provider. Deleted — a later Single Logout naming them has nothing to resolve
 * and is refused, which is the safe direction.
 */
class SamlIdpErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'saml_idp.subject';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        return ErasureStepResult::of($this->name(), [
            'saml_sessions' => SamlIdpSession::query()->where('subject_id', $request->subjectId)->toBase()->delete(),
            'saml_name_ids' => SamlIdpNameId::query()->where('subject_id', $request->subjectId)->toBase()->delete(),
        ]);
    }
}

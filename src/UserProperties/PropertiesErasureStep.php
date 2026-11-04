<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\UserProperties\Models\PropertyDocument;

class PropertiesErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'identity.user_properties';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        return ErasureStepResult::of($this->name(), [
            'user_property_documents' => PropertyDocument::query()->where('user_id', $request->subjectId)->toBase()->delete(),
        ]);
    }
}

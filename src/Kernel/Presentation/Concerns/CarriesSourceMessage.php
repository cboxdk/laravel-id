<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Presentation\Concerns;

use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

trait CarriesSourceMessage
{
    private ?SourceMessage $presentationMessage = null;

    public function sourceMessage(): ?SourceMessage
    {
        return $this->presentationMessage;
    }

    public function withSourceMessage(SourceMessage $message): static
    {
        $this->presentationMessage = $message;

        return $this;
    }
}

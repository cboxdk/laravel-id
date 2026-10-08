<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\GuideReturnKind;

/**
 * What the administrator copies back from their identity provider, and what that
 * provider calls it — "App Federation Metadata Url", "Download identity provider
 * metadata", "Issuer URL". The kind decides the form; the label tells them where to look.
 */
readonly class GuideReturns
{
    public function __construct(
        public GuideReturnKind $kind,

        /** The IdP's own label or button text, verbatim. */
        public string $theirs,
    ) {}
}

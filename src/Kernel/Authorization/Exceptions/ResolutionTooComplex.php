<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

/**
 * A check went deeper than the configured bound, or a list query visited more of the
 * graph than it may. Neither is answered with a guess: "no" would be wrong for a grant
 * that exists further down, and wrong in the other direction for a `but not`.
 */
final class ResolutionTooComplex extends AuthorizationModelException
{
    public static function depth(int $limit): self
    {
        return new self("Resolving this went more than {$limit} relations deep. Flatten the nesting, or raise cbox-id.fga.max_depth.");
    }

    public static function breadth(int $limit): self
    {
        return new self("Answering this would visit more than {$limit} objects. Narrow the query, or raise cbox-id.fga.max_expansion.");
    }

    public function errorCode(): string
    {
        return 'resolution_too_complex';
    }
}

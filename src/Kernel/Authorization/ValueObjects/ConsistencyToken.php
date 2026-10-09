<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

use Cbox\Id\Kernel\Authorization\Exceptions\InvalidConsistencyToken;

/**
 * "At least as fresh as this" — the revision a fine-grained write produced, handed back
 * so a later check can insist on seeing it.
 *
 * Every write to an environment's model (a tuple batch, a schema change) advances one
 * monotonic revision, and answers with a token naming it. A check given that token is
 * evaluated at that revision or a later one: it reads the primary connection when the
 * revision it first sees is older (a lagging read replica), and its cached answers are
 * keyed by revision, so nothing cached before the write can answer it. Without a token a
 * check is as fresh as the connection it reads — which, on one database, is the latest.
 *
 * The token names its environment by a short hash, so one environment's token is refused
 * by another rather than silently compared against a different counter. It is not a
 * secret and not a capability: a forged one can only ask for a revision that exists.
 *
 * Wire form: `<revision>.<environment tag>`, e.g. `42.9f3c1a7be2d0`.
 */
final readonly class ConsistencyToken
{
    private function __construct(
        public int $revision,
        private string $environmentTag,
    ) {}

    public static function for(string $environmentId, int $revision): self
    {
        return new self($revision, self::tag($environmentId));
    }

    /**
     * @throws InvalidConsistencyToken
     */
    public static function parse(string $token, string $environmentId): self
    {
        if (preg_match('/^(\d{1,18})\.([0-9a-f]{12})$/', $token, $match) !== 1) {
            throw new InvalidConsistencyToken('That consistency token is malformed.');
        }

        if (! hash_equals(self::tag($environmentId), $match[2])) {
            throw new InvalidConsistencyToken('That consistency token was issued by another environment.');
        }

        return new self((int) $match[1], $match[2]);
    }

    public function __toString(): string
    {
        return $this->revision.'.'.$this->environmentTag;
    }

    private static function tag(string $environmentId): string
    {
        return substr(hash('sha256', 'cbox-fga|'.$environmentId), 0, 12);
    }
}

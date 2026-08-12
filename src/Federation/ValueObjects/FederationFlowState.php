<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

/**
 * The two single-use values a federated login carries between the redirect and the
 * callback: `state`, which binds the answer to the browser that asked, and `nonce`,
 * which binds the id_token to this authorization rather than an earlier one.
 *
 * A pair, not `array{state: string, nonce: string}` threaded through two controllers and
 * a stash — because every reader was re-checking `is_string($stashed['state'] ?? null)`
 * for itself, and a reader that forgot compared a string against null and let a callback
 * through with no state at all.
 */
readonly class FederationFlowState
{
    public function __construct(
        public string $state,
        public string $nonce,
    ) {}

    /** A fresh pair, 128 bits each. */
    public static function fresh(): self
    {
        return new self(bin2hex(random_bytes(16)), bin2hex(random_bytes(16)));
    }

    /**
     * Parse whatever came out of a session or a cookie — both of which are `mixed` and
     * neither of which is trustworthy about shape.
     */
    public static function fromMixed(mixed $value): ?self
    {
        if (! is_array($value)) {
            return null;
        }

        $state = $value['state'] ?? null;
        $nonce = $value['nonce'] ?? null;

        if (! is_string($state) || $state === '' || ! is_string($nonce) || $nonce === '') {
            return null;
        }

        return new self($state, $nonce);
    }

    /**
     * @return array{state: string, nonce: string}
     */
    public function toArray(): array
    {
        return ['state' => $this->state, 'nonce' => $this->nonce];
    }

    /** Constant-time, because this is the CSRF comparison. */
    public function matches(string $state): bool
    {
        return $state !== '' && hash_equals($this->state, $state);
    }
}

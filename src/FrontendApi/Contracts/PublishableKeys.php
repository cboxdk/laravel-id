<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Contracts;

use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\Models\PublishableKey;

/**
 * Issuing, resolving and withdrawing the keys a browser is allowed to hold.
 */
interface PublishableKeys
{
    /**
     * Mint a key for the current environment, with its origins already attached.
     *
     * Origins are part of MINTING rather than a later step, because a key with no origins
     * is a key that works nowhere — and the shape where you create it, copy it into a
     * bundle, and then discover it is inert is a support ticket every time.
     *
     * @param  list<string>  $origins  raw input; normalized here, and anything unusable is refused
     */
    public function issue(string $name, KeyMode $mode, array $origins): PublishableKey;

    /**
     * The active key this value names, with its origins loaded, or null.
     *
     * Null covers every failure the caller must treat identically — unknown, revoked,
     * malformed, wrong environment — because distinguishing them in a response tells an
     * anonymous caller which keys exist.
     */
    public function resolve(string $key): ?PublishableKey;

    /** Withdraw a key. Idempotent; a key already revoked keeps its original timestamp. */
    public function revoke(string $id): void;

    /**
     * Replace a key's origin allow-list wholesale.
     *
     * @param  list<string>  $origins
     */
    public function setOrigins(string $id, array $origins): void;
}

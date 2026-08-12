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

    /**
     * Whether ANY active key in this environment names that origin.
     *
     * FOR THE PREFLIGHT, and only for it. A CORS preflight carries no custom headers — a
     * browser advertises their NAMES in `Access-Control-Request-Headers` and sends the
     * values only on the real request — so the key that identifies the caller does not
     * exist yet at preflight time. Answering on the origin alone is what makes this
     * channel usable from a browser at all, and it gives nothing away: a preflight grants
     * no access, the real request must still present a key that names this origin, and a
     * caller already sending an `Origin` header learns nothing by being told it is
     * registered — they own that origin.
     */
    public function allowsOrigin(string $origin): bool;

    /** Withdraw a key. Idempotent; a key already revoked keeps its original timestamp. */
    public function revoke(string $id): void;

    /**
     * Replace a key's origin allow-list wholesale.
     *
     * @param  list<string>  $origins
     */
    public function setOrigins(string $id, array $origins): void;
}

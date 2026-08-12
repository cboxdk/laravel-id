<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Illuminate\Http\Request;

/**
 * The person's name, for a provider that sends it exactly once and not in the assertion.
 *
 * Apple is the only member of the catalogue that does this, and it is not a quirk we can
 * work around later: `name` never appears in Apple's id_token. It arrives as a separate
 * `user` form field on the FIRST authorization — a JSON object holding `firstName` and
 * `lastName` — and never again for that person, no matter how many times they sign in.
 * A flow that reads only `code` and `state`, as this one did, throws away the only copy
 * that will ever exist: every Sign in with Apple account was created with a null name,
 * permanently, recoverable only if the person revokes the app in their Apple ID settings
 * and starts over.
 *
 * `ProviderTemplate::$profileOnFirstAuthorizationOnly` declared this on the catalogue
 * entry and nothing read it. This is the reader.
 *
 * WHAT ARRIVES HERE IS UNTRUSTED. It is a form field on a request we have not yet
 * verified anything about — no signature covers it, unlike every claim in the id_token —
 * so it is treated as a display name and nothing else: trimmed, length-capped, and only
 * ever used when the assertion carried no name of its own. It cannot decide who the
 * person is; `sub` does that, and `sub` comes from a signed token.
 */
class FirstAuthorizationProfile
{
    /** Long enough for any real name; short enough that the field is not a payload. */
    private const MAX_LENGTH = 120;

    /**
     * Merge the once-only name into the principal, when this provider sends one that way.
     */
    public function merge(Connection $connection, Request $request, FederatedPrincipal $principal): FederatedPrincipal
    {
        $provider = $connection->provider;

        if ($provider === null || ProviderCatalog::find($provider)?->profileOnFirstAuthorizationOnly !== true) {
            return $principal;
        }

        return $principal->withName($this->nameFrom($request->input('user')));
    }

    /**
     * Apple's shape: `{"name":{"firstName":"Dana","lastName":"Reeves"},"email":"…"}`,
     * sent as a JSON string in a form field. The email is ignored on purpose — the
     * id_token carries a signed one, and this field does not.
     */
    private function nameFrom(mixed $raw): ?string
    {
        if (is_string($raw)) {
            $raw = json_decode($raw, true);
        }

        if (! is_array($raw)) {
            return null;
        }

        $name = $raw['name'] ?? null;

        if (! is_array($name)) {
            return null;
        }

        $parts = [];

        foreach (['firstName', 'lastName'] as $key) {
            $part = $name[$key] ?? null;

            if (is_string($part) && trim($part) !== '') {
                $parts[] = trim($part);
            }
        }

        if ($parts === []) {
            return null;
        }

        return mb_substr(implode(' ', $parts), 0, self::MAX_LENGTH);
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

/**
 * A value the administrator must supply before a template becomes a real connection.
 *
 * Some providers have one issuer for the whole world — Google is `https://accounts.google.com`
 * for everybody. Others are per-installation: an Entra issuer names the directory, an
 * Okta issuer names the org, a Keycloak issuer names host and realm. Those cannot be
 * baked into the catalogue, and asking for "the issuer URL" instead defeats the point of
 * having a catalogue at all — the administrator is back to knowing the URL shape.
 *
 * So the template declares what it needs by name, with an example, and the issuer is
 * assembled from it. `{directory}` in the template is replaced by the value keyed
 * `directory`.
 */
readonly class ProviderParameter
{
    public function __construct(
        /** The placeholder in the issuer template, without braces. */
        public string $key,

        /** What to call it on screen — the provider's own word for it, not ours. */
        public string $label,

        /** One sentence: where the administrator finds this value. */
        public string $help,

        /** A realistic value, so the shape is obvious before anything is typed. */
        public string $example,
    ) {}
}

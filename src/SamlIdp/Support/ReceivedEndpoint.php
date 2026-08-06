<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Throwable;

/**
 * Where an inbound SAML message actually arrived, for `Destination` validation.
 *
 * SAML bindings §3.4.5.2/§3.5.5.2: "the recipient MUST then verify that the value
 * matches the location at which the message has been received." That is the
 * RECEIVING location — not whatever URL the IdP happens to publish right now. The
 * two diverge for a real, supported reason: {@see IdpDescriptor}'s endpoints follow
 * the environment issuer, so the moment a tenant federated on `{slug}.{base}`
 * verifies a custom domain, every SP that has not re-imported metadata keeps
 * addressing the old host — which is still live and still routes here. Comparing a
 * Destination only against the freshly-published URL turns that migration into an
 * IdP-wide refusal, which is precisely the outage the frozen EntityID exists to
 * prevent, reintroduced one attribute over.
 *
 * So a Destination is accepted when it names EITHER the URL the message was
 * received at OR the published endpoint, and nothing else. The received URL comes
 * from the framework's own request resolution (scheme + trusted Host + path), so it
 * is not free-form input, and it is compared in full: a message addressed to
 * another endpoint, another tenant or another IdP still fails.
 */
class ReceivedEndpoint
{
    /** Whether `$destination` addresses this endpoint, published at `$publishedUrl`. */
    public static function addresses(string $destination, string $publishedUrl): bool
    {
        if (hash_equals($publishedUrl, $destination)) {
            return true;
        }

        $received = self::url();

        return $received !== null && hash_equals($received, $destination);
    }

    /**
     * The URL (no query string) the current request arrived at, or null when there
     * is no HTTP request — a host driving the IdP API directly, or a queued job.
     */
    public static function url(): ?string
    {
        try {
            $url = request()->url();
        } catch (Throwable) {
            return null;
        }

        return $url !== '' ? $url : null;
    }
}

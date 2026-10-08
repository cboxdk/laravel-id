<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Contracts;

use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Cbox\Id\Webhooks\Support\StandardWebhookSignature;
use Cbox\Id\Webhooks\ValueObjects\RegisteredEndpoint;

/**
 * Choosing how an endpoint's deliveries are signed ({@see SignatureScheme}): at
 * registration, and afterwards.
 *
 * Its own contract rather than new methods on {@see WebhookRegistry}, because a host may
 * implement that interface and a new method would break it. The default binding is the
 * same database registry, which implements both. Registering through
 * {@see WebhookRegistry} is unchanged and always means {@see SignatureScheme::Cbox}.
 */
interface WebhookSigningSchemes
{
    /**
     * {@see WebhookRegistry::register()} with a chosen scheme. For
     * {@see SignatureScheme::StandardWebhooks} the reveal-once secret is a `whsec_` secret
     * that any Standard Webhooks library accepts as is.
     *
     * @param  list<string>  $eventTypes
     */
    public function registerWithScheme(string $organizationId, string $url, array $eventTypes, SignatureScheme $scheme): RegisteredEndpoint;

    /**
     * {@see WebhookRegistry::registerForEnvironment()} with a chosen scheme. Operator /
     * environment-plane callers only, for the same reason as that method.
     *
     * @param  list<string>  $eventTypes
     */
    public function registerForEnvironmentWithScheme(string $url, array $eventTypes, SignatureScheme $scheme): RegisteredEndpoint;

    /**
     * Move an endpoint OWNED by this organization (null = the environment's own) to
     * another scheme. Returns the updated endpoint, or null when nothing matched — a
     * mismatched owner is treated exactly like a missing id, as in
     * {@see WebhookRegistry::pause()}.
     *
     * The secret is NOT re-minted and NOT revealed again. The endpoint's owner already
     * holds it, and it works under either scheme: a hex secret becomes the Standard
     * Webhooks secret `'whsec_'.base64_encode($secret)` (lossless — see
     * {@see StandardWebhookSignature::secretFor()}), and a
     * `whsec_` secret keys the Cbox scheme with its literal characters.
     *
     * Takes effect from the next attempt: a pending delivery or a retry is signed under
     * the scheme the endpoint has when it is SENT, not when it was recorded.
     */
    public function changeSignatureScheme(string $endpointId, ?string $organizationId, SignatureScheme $scheme): ?WebhookEndpoint;
}

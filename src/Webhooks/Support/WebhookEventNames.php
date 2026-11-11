<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Enums\WebhookEventType;

/**
 * The two names of an outbound event: the internal one (`organization.member_added`) that
 * the domain emits, endpoints subscribe to and deliveries store, and the product-keyed one
 * (`id.organization.member_added`) of the Cbox URL/API standard.
 *
 * Which one goes ON THE WIRE (the body's `type`) is a deployment switch,
 * `cbox-id.webhooks.prefixed_event_types`, off by default. A receiver that knows only the
 * old names would drop every event the moment the new ones arrived, so the order is:
 * every receiver's laravel-id-client accepts both, every app is deployed with it, then the
 * operator turns the switch on. Nothing else changes with it: subscriptions, stored
 * deliveries, the delivery policy and the signature all keep the internal name, and an
 * endpoint may subscribe with either form.
 *
 * The mapping is `id.` + the internal name, except where the standard wants a past-tense
 * verb the old name lacked ({@see self::RENAMED}).
 */
final class WebhookEventNames
{
    /** The product key the standard puts in front of every event type. */
    public const PRODUCT_PREFIX = 'id.';

    /**
     * Internal name => the name after the product key, where it is not the same.
     *
     * @var array<string, string>
     */
    private const RENAMED = [
        'user.login' => 'user.signed_in',
    ];

    /** The product-keyed name of an internal event type. Idempotent. */
    public static function prefixed(string $type): string
    {
        if ($type === WebhookEventType::WILDCARD || str_starts_with($type, self::PRODUCT_PREFIX)) {
            return $type;
        }

        return self::PRODUCT_PREFIX.(self::RENAMED[$type] ?? $type);
    }

    /** The internal name of either form. Idempotent. */
    public static function internal(string $type): string
    {
        if (! str_starts_with($type, self::PRODUCT_PREFIX)) {
            return $type;
        }

        $name = substr($type, strlen(self::PRODUCT_PREFIX));
        $original = array_search($name, self::RENAMED, true);

        return is_string($original) ? $original : $name;
    }

    /** The name a receiver sees, under the current setting. */
    public static function onTheWire(string $type): string
    {
        return self::prefixedOnTheWire() ? self::prefixed($type) : self::internal($type);
    }

    public static function prefixedOnTheWire(): bool
    {
        return filter_var(config('cbox-id.webhooks.prefixed_event_types', false), FILTER_VALIDATE_BOOLEAN);
    }
}

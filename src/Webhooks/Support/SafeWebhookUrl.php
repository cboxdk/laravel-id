<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for outbound webhook URLs. The actual guarding — scheme/credential
 * checks, dual-stack resolution, private/reserved/cloud-metadata blocking, and
 * DNS pinning — lives in the shared, independently-tested `cboxdk/laravel-ssrf`
 * package. This adapter keeps the platform's own on/off toggle and domain
 * exception, so callers and their tests are unaffected.
 */
final class SafeWebhookUrl
{
    public static function isSafe(string $url): bool
    {
        try {
            self::assert($url);

            return true;
        } catch (UnsafeWebhookUrl) {
            return false;
        }
    }

    public static function assert(string $url): void
    {
        // A single-tenant/on-prem deployment can disable enforcement to deliver
        // to internal hosts (also disabled in the delivery tests). Keep it true in
        // any multi-tenant deployment.
        if (config('cbox-id.webhooks.verify_url', true) !== true) {
            return;
        }

        try {
            app(UrlGuard::class)->assertSafe($url);
        } catch (BlockedUrl $e) {
            throw UnsafeWebhookUrl::make($e->getMessage());
        }
    }
}

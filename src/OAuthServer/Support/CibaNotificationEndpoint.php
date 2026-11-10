<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;

/**
 * What a `backchannel_client_notification_endpoint` may be (CIBA Core §4): an absolute
 * https URL. Unlike a logout URI there is no plain-http exception for localhost — the spec
 * says https, and the request carries the client's bearer token.
 *
 * Checked at registration; the destination is checked again, with DNS pinned, at delivery
 * ({@see SafeCibaNotificationUrl}).
 */
class CibaNotificationEndpoint
{
    public const MAX_LENGTH = 2048;

    /**
     * @throws InvalidClientMetadata
     */
    public static function assertValid(string $uri): void
    {
        $name = 'backchannel_client_notification_endpoint';

        if (strlen($uri) > self::MAX_LENGTH) {
            throw self::invalid($name.' must be at most '.self::MAX_LENGTH.' characters', ':name must be at most :value1 characters', ['name' => $name, 'value1' => self::MAX_LENGTH]);
        }

        $parts = parse_url($uri);

        if ($parts === false || ! isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            throw self::invalid("{$name} is not an absolute URI: {$uri}", ':name is not an absolute URI: :uri', ['name' => $name, 'uri' => $uri]);
        }

        if (isset($parts['fragment']) || str_contains($uri, '#')) {
            throw self::invalid("{$name} must not contain a fragment: {$uri}", ':name must not contain a fragment: :uri', ['name' => $name, 'uri' => $uri]);
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw self::invalid("{$name} must not contain credentials: {$uri}", ':name must not contain credentials: :uri', ['name' => $name, 'uri' => $uri]);
        }

        if (strtolower($parts['scheme']) !== 'https') {
            throw self::invalid("{$name} must use https: {$uri}", ':name must use https: :uri', ['name' => $name, 'uri' => $uri]);
        }
    }

    /**
     * @param  array<string, string|int>  $parameters
     */
    private static function invalid(string $message, string $source, array $parameters): InvalidClientMetadata
    {
        return InvalidClientMetadata::metadata($message)->withSourceMessage(new SourceMessage($source, $parameters));
    }
}

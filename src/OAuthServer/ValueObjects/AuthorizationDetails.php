<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use JsonException;

/**
 * RFC 9396 (OAuth 2.0 Rich Authorization Requests) `authorization_details`: what one
 * specific authorization is FOR, carried onto the access token as a claim (§9.1) so the
 * resource server can check that this token approves exactly the thing it is asked to do
 * (one deployment plan, one payment) and nothing else.
 *
 * Accepted at the token endpoint on a token exchange (§6, §7): the client already holds
 * the person's token and narrows it to one action. Each entry is an object with a string
 * `type` the client registered (§10, `authorization_details_types`); the rest of an entry
 * is the type's own fields, held to plain JSON of bounded size and depth because it lands
 * in a signed token and in every log that prints one.
 */
readonly class AuthorizationDetails
{
    private const MAX_ENTRIES = 10;

    private const MAX_BYTES = 4096;

    private const MAX_DEPTH = 4;

    /** @param non-empty-list<array<string, mixed>> $entries */
    private function __construct(public array $entries) {}

    /**
     * Parse the request parameter: a JSON array of objects (RFC 9396 §2).
     *
     * @throws InvalidTokenExchange `invalid_authorization_details` (§5) on anything else
     */
    public static function fromRequest(mixed $raw): self
    {
        if (is_string($raw)) {
            if (strlen($raw) > self::MAX_BYTES) {
                throw InvalidTokenExchange::invalidAuthorizationDetails('authorization_details is too large.');
            }

            try {
                $raw = json_decode($raw, true, self::MAX_DEPTH + 2, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                throw InvalidTokenExchange::invalidAuthorizationDetails('authorization_details is not valid JSON.');
            }
        }

        if (! is_array($raw) || $raw === [] || ! array_is_list($raw) || count($raw) > self::MAX_ENTRIES) {
            throw InvalidTokenExchange::invalidAuthorizationDetails('authorization_details must be a JSON array of 1 to 10 objects.');
        }

        $entries = [];

        foreach ($raw as $entry) {
            if (! is_array($entry) || $entry === [] || array_is_list($entry)) {
                throw InvalidTokenExchange::invalidAuthorizationDetails('Each authorization_details entry must be a JSON object.');
            }

            $type = $entry['type'] ?? null;

            if (! is_string($type) || preg_match('/^[A-Za-z0-9._:\/-]{1,128}$/D', $type) !== 1) {
                throw InvalidTokenExchange::invalidAuthorizationDetails('Each authorization_details entry needs a string type.');
            }

            if (! self::plain($entry, 1)) {
                throw InvalidTokenExchange::invalidAuthorizationDetails('authorization_details may hold only strings, numbers, booleans, arrays and objects, nested at most four deep.');
            }

            /** @var array<string, mixed> $entry */
            $entries[] = $entry;
        }

        $encoded = json_encode($entries, JSON_UNESCAPED_SLASHES);

        if ($encoded === false || strlen($encoded) > self::MAX_BYTES) {
            throw InvalidTokenExchange::invalidAuthorizationDetails('authorization_details is too large.');
        }

        return new self($entries);
    }

    /** @return list<string> the distinct types, in the order first seen */
    public function types(): array
    {
        $types = [];

        foreach ($this->entries as $entry) {
            $type = $entry['type'];

            if (is_string($type) && ! in_array($type, $types, true)) {
                $types[] = $type;
            }
        }

        return $types;
    }

    /** @return non-empty-list<array<string, mixed>> the claim value (RFC 9396 §9.1) and the response member (§7) */
    public function claim(): array
    {
        return $this->entries;
    }

    private static function plain(mixed $value, int $depth): bool
    {
        if (is_string($value) || is_int($value) || is_float($value) || is_bool($value)) {
            return true;
        }

        if (! is_array($value) || $depth > self::MAX_DEPTH) {
            return false;
        }

        foreach ($value as $key => $item) {
            if (is_string($key) && strlen($key) > 128) {
                return false;
            }

            if (! self::plain($item, $depth + 1)) {
                return false;
            }
        }

        return true;
    }
}

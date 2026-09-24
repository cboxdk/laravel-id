<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Organization\Exceptions\InvalidApiKeyPrefix;
use Stringable;

/**
 * The prefix an app's customer API keys carry: `ctx_live` makes keys shaped
 * `ctx_live_<48 random characters>`.
 *
 * FORMAT: `^[a-z][a-z0-9]{1,15}_(live|test)$` — a lowercase root of 2 to 16
 * characters naming the app, then a `live` or `test` marker. The marker is a label for
 * people and secret scanners, nothing more: the ENVIRONMENT is what separates a staging
 * key from a production one, and a key only ever verifies in the environment it was
 * issued in. Declare `_test` on the clients of your non-production environments so a
 * leaked key says which kind it is at a glance.
 *
 * The root `cbid` is reserved for the platform's own credentials (`cbid_pat_`,
 * `cbid_env_`, `cbid_org_`), so an app key can never be mistaken for one of them.
 */
readonly class ApiKeyPrefix implements Stringable
{
    /** The pattern a prefix must match. */
    public const PATTERN = '/^[a-z][a-z0-9]{1,15}_(live|test)$/';

    /** Characters of randomness after the prefix (base62, ~285 bits). */
    public const RANDOM_LENGTH = 48;

    /** Roots an app may not claim. */
    private const RESERVED_ROOTS = ['cbid'];

    private function __construct(public string $value) {}

    /**
     * @throws InvalidApiKeyPrefix when the value does not match {@see self::PATTERN}
     *                             or uses a reserved root
     */
    public static function of(string $value): self
    {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw InvalidApiKeyPrefix::malformed($value);
        }

        $root = substr($value, 0, (int) strrpos($value, '_'));

        if (in_array($root, self::RESERVED_ROOTS, true)) {
            throw InvalidApiKeyPrefix::reserved($value);
        }

        return new self($value);
    }

    /** {@see self::of()} without the exception: null for anything invalid. */
    public static function tryFrom(string $value): ?self
    {
        try {
            return self::of($value);
        } catch (InvalidApiKeyPrefix) {
            return null;
        }
    }

    /**
     * Whether a presented string has the shape of a customer API key at all — a valid
     * prefix, an underscore, and exactly {@see self::RANDOM_LENGTH} base62 characters.
     * A cheap refusal before anything touches the database.
     */
    public static function isKeyShaped(string $plaintext): bool
    {
        if (preg_match('/^([a-z][a-z0-9]{1,15}_(?:live|test))_[A-Za-z0-9]{'.self::RANDOM_LENGTH.'}$/', $plaintext, $matches) !== 1) {
            return false;
        }

        return self::tryFrom($matches[1]) !== null;
    }

    /** Whether the prefix is marked for non-production use. */
    public function isTest(): bool
    {
        return str_ends_with($this->value, '_test');
    }

    public function __toString(): string
    {
        return $this->value;
    }
}

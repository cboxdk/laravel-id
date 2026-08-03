<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use ArrayIterator;
use Cbox\Id\Federation\Enums\ProviderCapability;
use Countable;
use IteratorAggregate;
use Traversable;

/**
 * The set of things one catalogue provider can be used for.
 *
 * A set rather than a list: a capability is either present or it is not, and asking the
 * same question twice must not be able to give two answers. Constructing it from
 * duplicates collapses them rather than refusing, because the duplicates come from
 * composing derived answers and a throw there would be noise, not a defect.
 *
 * Typed because the console branches on it. `in_array('directory', $strings, true)` is
 * one typo away from silently hiding every directory provider, and neither PHPStan nor a
 * reviewer would see it; `has(ProviderCapability::Directory)` cannot be misspelled.
 * Strings appear only at {@see self::values()}, which exists for serialization edges.
 *
 * @implements IteratorAggregate<int, ProviderCapability>
 */
readonly class ProviderCapabilities implements Countable, IteratorAggregate
{
    /** @var list<ProviderCapability> */
    public array $capabilities;

    public function __construct(ProviderCapability ...$capabilities)
    {
        $unique = [];

        foreach ($capabilities as $capability) {
            $unique[$capability->value] = $capability;
        }

        $this->capabilities = array_values($unique);
    }

    public function has(ProviderCapability $capability): bool
    {
        return in_array($capability, $this->capabilities, true);
    }

    public function isEmpty(): bool
    {
        return $this->capabilities === [];
    }

    /**
     * The capabilities as their stored strings — for a wire payload or a query, never for
     * a decision in PHP. Use {@see self::has()} for those.
     *
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(static fn (ProviderCapability $c): string => $c->value, $this->capabilities);
    }

    /** @return Traversable<int, ProviderCapability> */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->capabilities);
    }

    public function count(): int
    {
        return count($this->capabilities);
    }
}

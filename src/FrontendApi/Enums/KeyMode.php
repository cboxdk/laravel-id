<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Enums;

/**
 * Whether a publishable key drives a real sign-in or a rehearsal of one.
 *
 * The mode is IN THE KEY ITSELF — `pk_test_…` / `pk_live_…` — so a person reading a diff,
 * a bundle, or a support ticket can see which one they are looking at without resolving
 * anything. A single key plus a boolean somewhere else is one config mistake away from a
 * staging page driving production sign-ins, and that mistake is invisible until it is
 * expensive.
 */
enum KeyMode: string
{
    case Test = 'test';
    case Live = 'live';

    /** The prefix a key of this mode carries — `pk_test_`, `pk_live_`. */
    public function prefix(): string
    {
        return 'pk_'.$this->value.'_';
    }

    public function label(): string
    {
        return match ($this) {
            self::Test => 'Test',
            self::Live => 'Live',
        };
    }

    /**
     * The mode a key value declares, or null when it declares none we know.
     *
     * Read from the prefix rather than from the stored column on purpose: this is the
     * function that decides whether a string off the wire is even shaped like one of our
     * keys, before any lookup happens.
     */
    public static function fromKey(string $key): ?self
    {
        foreach (self::cases() as $case) {
            if (str_starts_with($key, $case->prefix())) {
                return $case;
            }
        }

        return null;
    }
}

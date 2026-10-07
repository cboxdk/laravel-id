<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use SensitiveParameter;

/**
 * The master keys a deployment holds: the CURRENT one, which seals everything new, and
 * the PREVIOUS ones, which only ever open what was sealed before a rotation.
 *
 * A rotation is therefore a configuration change, never a flag day: set the new key as
 * `CBOX_ID_CRYPTO_KEY`, move the old one into `CBOX_ID_CRYPTO_PREVIOUS_KEYS`, deploy, run
 * `cbox-id:crypto:rewrap`, and only once `cbox-id:doctor` reports nothing left under a
 * previous key drop it from the list. Every ciphertext stays readable throughout.
 */
readonly class MasterKeySet
{
    /**
     * @param  list<MasterKey>  $previous  oldest last; never contains the current key
     */
    public function __construct(
        public MasterKey $current,
        public array $previous = [],
    ) {}

    /**
     * Build the set from configuration. `$previous` is a list of keys or one string of
     * comma-separated keys (the form an env var can carry). A previous entry equal to the
     * current key, or repeated, is dropped rather than refused — re-listing the live key
     * while mid-rotation is a common, harmless slip.
     *
     * @throws CryptoConfigurationException when the current key is missing/invalid, or a
     *                                      previous key is not a valid 32-byte base64 key
     */
    public static function fromConfig(#[SensitiveParameter] mixed $current, #[SensitiveParameter] mixed $previous = null): self
    {
        $currentKey = MasterKey::tryFromConfigured($current);

        if ($currentKey === null) {
            throw CryptoConfigurationException::missingKey();
        }

        $seen = [$currentKey->id => true];
        $previousKeys = [];

        foreach (self::entries($previous) as $position => $entry) {
            $key = MasterKey::tryFromConfigured($entry);

            if ($key === null) {
                throw CryptoConfigurationException::invalidPreviousKey($position);
            }

            if (isset($seen[$key->id])) {
                continue;
            }

            $seen[$key->id] = true;
            $previousKeys[] = $key;
        }

        return new self($currentKey, $previousKeys);
    }

    /**
     * Current first, then the previous keys in configured order.
     *
     * @return list<MasterKey>
     */
    public function all(): array
    {
        return [$this->current, ...$this->previous];
    }

    public function find(string $id): ?MasterKey
    {
        foreach ($this->all() as $key) {
            if (hash_equals($key->id, $id)) {
                return $key;
            }
        }

        return null;
    }

    /** @return list<string> */
    public function previousIds(): array
    {
        return array_map(static fn (MasterKey $key): string => $key->id, $this->previous);
    }

    /**
     * @return list<string>
     */
    private static function entries(#[SensitiveParameter] mixed $previous): array
    {
        if (is_string($previous)) {
            $previous = explode(',', $previous);
        }

        if (! is_array($previous)) {
            return [];
        }

        $entries = [];

        foreach ($previous as $entry) {
            if (is_string($entry) && trim($entry) !== '') {
                $entries[] = trim($entry);
            }
        }

        return $entries;
    }
}

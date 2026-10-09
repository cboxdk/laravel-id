<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\ValueObjects;

use Carbon\CarbonImmutable;

/**
 * What one pull asks of an HR system beyond its credentials.
 *
 * Read from the directory's `mappings` (`mappings.hris`), never from the credentials: none
 * of this is secret, and an administrator changing which fields pass through must not have
 * to re-enter an API key to do it.
 */
readonly class HrisSyncOptions
{
    /**
     * @param  list<string>  $customAttributes  HR-system field names to pass through onto the directory user, verbatim
     * @param  array<string, string>  $fieldMap  for systems whose field names are the customer's own (a Workday report): our field => their column
     */
    public function __construct(
        /**
         * Only employees changed at or after this instant, when the provider can filter so.
         * Null asks for everyone — and only a full pull may deprovision the people it did
         * not see.
         */
        public ?CarbonImmutable $changedSince = null,
        public array $customAttributes = [],
        public array $fieldMap = [],
    ) {}

    public function incremental(): bool
    {
        return $this->changedSince !== null;
    }

    public function withChangedSince(?CarbonImmutable $since): self
    {
        return new self($since, $this->customAttributes, $this->fieldMap);
    }

    /**
     * The options stored on a directory's `mappings.hris`, tolerating anything malformed.
     *
     * @param  array<mixed>  $mappings  the directory's whole `mappings` column
     */
    public static function fromMappings(array $mappings): self
    {
        $hris = is_array($mappings['hris'] ?? null) ? $mappings['hris'] : [];

        $custom = [];

        foreach (is_array($hris['custom_attributes'] ?? null) ? $hris['custom_attributes'] : [] as $name) {
            if (is_string($name) && trim($name) !== '') {
                $custom[] = trim($name);
            }
        }

        $map = [];

        foreach (is_array($hris['field_map'] ?? null) ? $hris['field_map'] : [] as $ours => $theirs) {
            if (is_string($ours) && is_string($theirs) && trim($theirs) !== '') {
                $map[$ours] = trim($theirs);
            }
        }

        return new self(null, array_values(array_unique($custom)), $map);
    }
}

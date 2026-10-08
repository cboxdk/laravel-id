<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

/**
 * One operation of a SCIM `BulkRequest` (RFC 7644 §3.7), read off the wire.
 *
 * Parsing never throws: an operation that is malformed — an unknown `method`, a `path`
 * that is not `/Users[/{id}]` or `/Groups[/{id}]`, a POST without `bulkId` or `data` —
 * is kept with the reason in {@see $invalid}, so it fails on its own as a `400` entry
 * of the response while the rest of the request proceeds.
 */
readonly class ScimBulkOperation
{
    private const METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    private const REFERENCE_PREFIX = 'bulkId:';

    /**
     * @param  string|null  $resource  `Users` or `Groups`
     * @param  array<array-key, mixed>  $data
     */
    public function __construct(
        public string $method,
        public ?string $bulkId,
        public ?string $version,
        public ?string $resource,
        public ?string $id,
        public array $data,
        public ?string $invalid = null,
    ) {}

    public static function parse(mixed $raw): self
    {
        if (! is_array($raw)) {
            return new self('', null, null, null, null, [], 'Every member of "Operations" must be an operation object (RFC 7644 §3.7).');
        }

        // Sub-attribute names are case-insensitive like every other SCIM attribute name
        // (RFC 7643 §2.1); the METHOD is an HTTP method and is matched as one.
        $raw = array_change_key_case($raw, CASE_LOWER);
        $method = is_string($raw['method'] ?? null) ? strtoupper(trim($raw['method'])) : '';
        $bulkId = is_string($raw['bulkid'] ?? null) && $raw['bulkid'] !== '' ? $raw['bulkid'] : null;
        $version = is_string($raw['version'] ?? null) && $raw['version'] !== '' ? $raw['version'] : null;
        $path = is_string($raw['path'] ?? null) ? trim($raw['path']) : '';
        $data = $raw['data'] ?? null;

        $invalid = static fn (string $reason, ?string $resource = null, ?string $id = null): self => new self($method, $bulkId, $version, $resource, $id, [], $reason);

        if (! in_array($method, self::METHODS, true)) {
            return $invalid('"method" must be one of POST, PUT, PATCH or DELETE.');
        }

        if (preg_match('#^/?(Users|Groups)(?:/([^/]+))?/?$#i', $path, $m) !== 1) {
            return $invalid('"path" must name /Users or /Groups, or one resource of either.');
        }

        $resource = strcasecmp($m[1], 'Groups') === 0 ? 'Groups' : 'Users';
        $id = ($m[2] ?? '') === '' ? null : rawurldecode($m[2]);

        // §3.7: POST targets the resource-type endpoint; every other method one resource.
        if ($method === 'POST' && $id !== null) {
            return $invalid('A POST operation must target /Users or /Groups.', $resource);
        }

        if ($method !== 'POST' && $id === null) {
            return $invalid(sprintf('A %s operation must target one resource, e.g. /%s/{id}.', $method, $resource), $resource);
        }

        // §3.7: "bulkId … REQUIRED when "method" is "POST"" — without it the client
        // cannot tell which created resource is which.
        if ($method === 'POST' && $bulkId === null) {
            return $invalid('A POST operation must carry a "bulkId".', $resource);
        }

        if ($method === 'DELETE') {
            return new self($method, $bulkId, $version, $resource, $id, []);
        }

        // §3.7.3's own example sends a PATCH's operations as a bare list; read it as the
        // PatchOp message it stands for.
        if ($method === 'PATCH' && is_array($data) && array_is_list($data)) {
            $data = ['Operations' => $data];
        }

        if (! is_array($data) || $data === []) {
            return $invalid(sprintf('A %s operation must carry "data".', $method), $resource, $id);
        }

        return new self($method, $bulkId, $version, $resource, $id, $data);
    }

    /**
     * This operation, refused for `$reason`.
     */
    public function invalidate(string $reason): self
    {
        return new self($this->method, $this->bulkId, $this->version, $this->resource, $this->id, [], $reason);
    }

    /**
     * Every `bulkId` this operation refers to — in its path and anywhere in its data.
     *
     * @return list<string>
     */
    public function references(): array
    {
        $found = [];

        if ($this->id !== null && ($reference = self::reference($this->id)) !== null) {
            $found[$reference] = true;
        }

        $data = $this->data;

        array_walk_recursive($data, static function (mixed $value) use (&$found): void {
            if (is_string($value) && ($reference = self::reference($value)) !== null) {
                $found[$reference] = true;
            }
        });

        return array_map(strval(...), array_keys($found));
    }

    /**
     * This operation with every `bulkId:<x>` replaced by the id `<x>` was created as.
     *
     * @param  array<string, string>  $ids
     */
    public function resolve(array $ids): self
    {
        $substitute = static function (mixed $value) use ($ids): mixed {
            if (is_string($value) && ($reference = self::reference($value)) !== null) {
                return $ids[$reference] ?? $value;
            }

            return $value;
        };

        $id = $this->id === null ? null : $substitute($this->id);

        return new self(
            $this->method,
            $this->bulkId,
            $this->version,
            $this->resource,
            is_string($id) ? $id : $this->id,
            self::map($this->data, $substitute),
            $this->invalid,
        );
    }

    /**
     * The fields every BulkResponse entry echoes back (§3.7.3).
     *
     * @return array<string, mixed>
     */
    public function summary(): array
    {
        return array_filter([
            'method' => $this->method === '' ? null : $this->method,
            'bulkId' => $this->bulkId,
        ], static fn (?string $value): bool => $value !== null);
    }

    private static function reference(string $value): ?string
    {
        if (! str_starts_with($value, self::REFERENCE_PREFIX)) {
            return null;
        }

        $reference = substr($value, strlen(self::REFERENCE_PREFIX));

        return $reference === '' ? null : $reference;
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  callable(mixed): mixed  $substitute
     * @return array<array-key, mixed>
     */
    private static function map(array $data, callable $substitute): array
    {
        foreach ($data as $key => $value) {
            $data[$key] = is_array($value) ? self::map($value, $substitute) : $substitute($value);
        }

        return $data;
    }
}

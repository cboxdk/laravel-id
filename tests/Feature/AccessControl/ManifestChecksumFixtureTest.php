<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Manifest\DeclaredPermission;
use Cbox\Id\AccessControl\Manifest\DeclaredRole;
use Cbox\Id\AccessControl\Manifest\Manifest;

/**
 * Locks Manifest::checksum() to the shared cross-SDK fixture. The same file is
 * asserted against by id-js, id-python and id-go, so this test is what keeps the four
 * canonicalizations byte-for-byte identical: if the PHP reference ever drifts, this
 * fails here before the SDKs diverge in the field.
 *
 * @return array<string, array{0: array<string, mixed>}>
 */
function manifestHashFixtureCases(): array
{
    $path = dirname(__DIR__, 2).'/Fixtures/AccessControl/manifest_hash.json';
    /** @var array{cases: list<array<string, mixed>>} $data */
    $data = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    $dataset = [];
    foreach ($data['cases'] as $case) {
        // Wrap each case as a single argument, keyed by name for readable output.
        $dataset[$case['name']] = [$case];
    }

    return $dataset;
}

it('produces the shared cross-SDK checksum for every fixture manifest', function (array $case): void {
    $permissions = array_map(
        static fn (array $p): DeclaredPermission => new DeclaredPermission($p['key'], $p['description']),
        $case['permissions'],
    );
    $roles = array_map(
        static fn (array $r): DeclaredRole => new DeclaredRole($r['key'], $r['name'], $r['description'], $r['permissions']),
        $case['roles'],
    );

    $manifest = new Manifest('1', $permissions, $roles);

    expect($manifest->checksum())->toBe($case['sha256'])
        ->and(substr($manifest->checksum(), 0, 16))->toBe($case['version']);
})->with(manifestHashFixtureCases());

<?php

declare(strict_types=1);

use Cbox\Id\Scim\ScimSchema;

it('builds a User resource with the core schema URN and externalId leading', function (): void {
    $resource = ScimSchema::userResource('ext-1', [
        'userName' => 'a@example.com',
        'active' => true,
    ]);

    expect($resource['schemas'])->toBe([ScimSchema::USER_URN])
        ->and($resource['externalId'])->toBe('ext-1')
        ->and($resource['userName'])->toBe('a@example.com')
        ->and($resource['active'])->toBeTrue();
});

it('emits the enterprise extension under its URN key when present', function (): void {
    $resource = ScimSchema::userResource('ext-2', [
        'userName' => 'b@example.com',
        'enterprise' => ['department' => 'Engineering'],
    ]);

    expect($resource['schemas'])->toBe([ScimSchema::USER_URN, ScimSchema::ENTERPRISE_URN])
        ->and($resource[ScimSchema::ENTERPRISE_URN])->toBe(['department' => 'Engineering'])
        // The inline key is not leaked as a bare attribute.
        ->and($resource)->not->toHaveKey('enterprise');
});

it('builds a PatchOp message with the RFC 7644 schema and operations', function (): void {
    $patch = ScimSchema::patchOp([ScimSchema::replace('displayName', 'New Name'), ScimSchema::setActive(false)]);

    expect($patch['schemas'])->toBe([ScimSchema::PATCH_OP_URN])
        ->and($patch['Operations'][0])->toBe(['op' => 'replace', 'path' => 'displayName', 'value' => 'New Name'])
        ->and($patch['Operations'][1])->toBe(['op' => 'replace', 'path' => 'active', 'value' => false]);
});

it('escapes a filter value so it cannot break out of the quoted literal', function (): void {
    $filter = ScimSchema::equalityFilter('externalId', 'a"b\\c');

    expect($filter)->toBe('externalId eq "a\\"b\\\\c"');
});

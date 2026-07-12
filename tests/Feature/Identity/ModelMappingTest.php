<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Tests\Fixtures\CustomUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('uses the package user model by default', function (): void {
    expect(app(UserDirectory::class)->create('a@x.test'))->toBeInstanceOf(User::class);
});

it('resolves a consumer-configured user model', function (): void {
    config(['cbox-id.models.user' => CustomUser::class]);

    $created = app(UserDirectory::class)->create('custom@x.test');
    $found = app(UserDirectory::class)->findByEmail('custom@x.test');

    expect($created)->toBeInstanceOf(CustomUser::class)
        ->and($created->isCustom())->toBeTrue()
        ->and($found)->toBeInstanceOf(CustomUser::class);
});

it('ignores an invalid model override and falls back to the package model', function (): void {
    config(['cbox-id.models.user' => 'NotAModelClass']);

    expect(app(UserDirectory::class)->create('b@x.test'))->toBeInstanceOf(User::class);
});

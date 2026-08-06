<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\DatabaseSubjects;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Tests\Fixtures\ArraySubjects;
use Cbox\Id\Tests\Fixtures\CustomUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('returns an opaque Subject, never a host model', function (): void {
    $subject = app(Subjects::class)->create('a@x.test', 'A');

    expect($subject)->toBeInstanceOf(Subject::class)
        ->and($subject->email)->toBe('a@x.test');
});

it('persists through a consumer-configured user model in the default store', function (): void {
    config(['cbox-id.models.user' => CustomUser::class]);

    $subject = app(Subjects::class)->create('custom@x.test');

    expect(CustomUser::query()->whereKey($subject->id)->first()?->isCustom())->toBeTrue();
});

it('ignores an invalid model override and falls back to the package model', function (): void {
    config(['cbox-id.models.user' => 'NotAModelClass']);

    $subject = app(Subjects::class)->create('b@x.test');

    expect(User::query()->whereKey($subject->id)->exists())->toBeTrue();
});

it('lets a host bind its own subject resolver and never touches the users table', function (): void {
    config(['cbox-id.subject.resolver' => ArraySubjects::class]);

    $resolver = app(Subjects::class);
    $subject = $resolver->create('reseller@x.test', 'Reseller');

    expect($resolver)->toBeInstanceOf(ArraySubjects::class)
        ->and($subject->id)->toStartWith('reseller:')            // host-owned, namespaced id
        ->and($resolver->findByEmail('reseller@x.test')?->id)->toBe($subject->id)
        ->and(User::query()->count())->toBe(0);                  // package store untouched
});

it('falls back to the default resolver when the configured resolver is invalid', function (): void {
    config(['cbox-id.subject.resolver' => 'NotAResolver']);

    expect(app(Subjects::class))->toBeInstanceOf(DatabaseSubjects::class);
});

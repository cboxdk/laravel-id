<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * A hook point is chosen by a human in a console. Without a label the view renders
 * `$case->name` and an admin picks between "PrePasswordChange" and
 * "PostPasswordChange" — PHP identifiers as product copy. These pin that every case
 * carries copy, so adding a seventh point cannot silently ship an identifier.
 */
it('gives every hook point human copy, not a PHP identifier', function (HookPoint $point): void {
    expect($point->label())->not->toBe($point->name)
        ->and($point->label())->not->toBe($point->value)
        ->and($point->label())->not->toMatch('/[_A-Z]{2}|^[A-Z][a-z]+[A-Z]/')  // snake_case or StudlyCase
        ->and($point->description())->toEndWith('.');
})->with(HookPoint::cases());

it('says in the description whether a hook can refuse', function (HookPoint $point): void {
    // An admin wiring a URL that can stop people signing in must be able to see that
    // it can, from the same line they choose it on.
    expect(strtolower($point->description()))
        ->toContain($point->vetoable() ? 'refuse' : 'cannot refuse');
})->with(HookPoint::cases());

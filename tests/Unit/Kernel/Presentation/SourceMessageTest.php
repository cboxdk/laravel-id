<?php

declare(strict_types=1);

use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use Cbox\Id\OAuthServer\Exceptions\InvalidApiDefinition;

it('keeps parameter-looking user data literal when rendering structured source text', function (): void {
    $message = new SourceMessage(':name has :count roles: :roles.', [
        'name' => 'Acme :count',
        'count' => 2,
        'roles' => [new SourceMessage(':role', ['role' => 'Billing :name']), new SourceMessage('Viewer')],
    ]);
    expect($message->english())->toBe('Acme :count has 2 roles: Billing :name, Viewer.');
});

it('adds presentation metadata without changing framework exception messages', function (): void {
    $password = PolicyViolation::tooShort(17);
    expect($password->getMessage())->toBe('The password must be at least 17 characters.')
        ->and($password->sourceMessage()?->template)->toBe('The password must be at least :minLength characters.')
        ->and($password->sourceMessage()?->parameters)->toBe(['minLength' => 17]);
    $identifier = 'https://example.test/:identifier';
    $api = InvalidApiDefinition::identifierTaken($identifier);
    expect($api->sourceMessage()?->english())->toBe($api->getMessage())
        ->and($api->sourceMessage()?->parameters)->toBe(['identifier' => $identifier]);
});

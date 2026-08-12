<?php

declare(strict_types=1);

use Cbox\Id\Migration\Sources\HttpCredentialSource;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    // The guard is ON in production and refuses a host that does not resolve, which is
    // correct and makes a fake unreachable. Switched off here so these tests are about
    // the transport's own behaviour; the pinning itself is the SSRF package's to prove.
    config()->set('cbox-id.migration.verify_url', false);
});

function httpSource(string $url = 'https://legacy.acme.test/verify'): HttpCredentialSource
{
    return new HttpCredentialSource(app(Factory::class), $url, 'shared-secret');
}

it('accepts what the handler says yes to', function (): void {
    Http::fake(['*' => Http::response(['email' => 'ada@legacy.test', 'name' => 'Ada', 'email_verified' => true], 200)]);

    $user = httpSource()->verify('ada@legacy.test', 'correct horse');

    expect($user?->email)->toBe('ada@legacy.test')
        ->and($user?->emailVerified)->toBeTrue();
});

/**
 * The same construction the external-action hooks sign with, so a customer who has written
 * a verifier for one can reuse it here verbatim rather than implementing a second scheme.
 */
it('signs the request the way the rest of the platform signs outbound calls', function (): void {
    Http::fake(['*' => Http::response(['email' => 'ada@legacy.test'], 200)]);

    httpSource()->verify('ada@legacy.test', 'pw');

    // RECOMPUTED, not pattern-matched. Asserting the header merely starts with `t=` and
    // contains `,v1=` passes for a constant, for a digest over the wrong key, and for one
    // over a public string — every way this signature can be worthless while looking right.
    Http::assertSent(function ($request): bool {
        [$timestamp, $signature] = explode(',', (string) $request->header('X-Cbox-Signature')[0]);

        return hash_equals(
            'v1='.hash_hmac('sha256', substr($timestamp, 2).'.'.$request->body(), 'shared-secret'),
            $signature,
        );
    });
});

it('sends the password it was given, in the body it signed', function (): void {
    Http::fake(['*' => Http::response(['email' => 'ada@legacy.test'], 200)]);

    httpSource()->verify('ada@legacy.test', 'correct horse');

    // `verify()` and `find()` differ on the wire by this one key, and nothing else. A
    // transport that dropped the password would still satisfy every other test in this
    // file while asking the handler a question it cannot answer.
    Http::assertSent(fn ($request): bool => $request->data() === [
        'email' => 'ada@legacy.test',
        'password' => 'correct horse',
    ]);
});

it('asks without a password when it only wants to know whether the address is known', function (): void {
    Http::fake(['*' => Http::response(['email' => 'ada@legacy.test'], 200)]);

    httpSource()->find('ada@legacy.test');

    Http::assertSent(fn ($request): bool => $request->data() === ['email' => 'ada@legacy.test']);
});

/**
 * THE HANDLER ANSWERS ABOUT THE ADDRESS IT WAS ASKED ABOUT, or it does not answer.
 *
 * The handler is the customer's code. A loose lookup in it — a LIKE, a join that dropped a
 * WHERE, an alias table — would otherwise let somebody who knows one old password be
 * migrated in as whichever identity that query happened to return.
 */
it('refuses a person the handler returned who is not the person it was asked about', function (): void {
    Http::fake(['*' => Http::response(['email' => 'admin@acme.test'], 200)]);

    expect(httpSource()->verify('attacker@legacy.test', 'pw'))->toBeNull();
});

it('accepts the same address back in different case or with stray whitespace', function (): void {
    Http::fake(['*' => Http::response(['email' => '  Ada@Legacy.test '], 200)]);

    expect(httpSource()->verify('ada@legacy.test', 'pw')?->email)->toBe('  Ada@Legacy.test ');
});

/**
 * A credential over plain http is readable by everything on the path. Refused rather than
 * warned: the failure mode of "we logged it and sent it anyway" is that nobody reads the
 * log until afterwards.
 */
it('refuses to send a password over plain http, and never calls out', function (): void {
    Http::fake();

    expect(httpSource('http://legacy.acme.test/verify')->verify('ada@legacy.test', 'pw'))->toBeNull();

    Http::assertNothingSent();
});

it('says no when the handler refuses, whatever status it uses', function (int $status): void {
    Http::fake(['*' => Http::response(['error' => 'nope'], $status)]);

    expect(httpSource()->verify('ada@legacy.test', 'pw'))->toBeNull();
})->with([401, 403, 404, 500, 503]);

/**
 * A handler that answers 200 with nothing usable has said no in an unhelpful way. Treated
 * as no rather than as an error, because the alternative is throwing on a login path over
 * somebody else's response shape.
 */
it('says no to a 200 with no usable person in it', function (mixed $body): void {
    Http::fake(['*' => Http::response($body, 200)]);

    expect(httpSource()->verify('ada@legacy.test', 'pw'))->toBeNull();
})->with([
    'empty' => [[]],
    'no email' => [['name' => 'Ada']],
    'blank email' => [['email' => '']],
    'not an object' => ['just a string'],
]);

it('fails closed when the handler is unreachable', function (): void {
    Http::fake(fn () => throw new ConnectionException('timed out'));

    expect(httpSource()->verify('ada@legacy.test', 'pw'))->toBeNull();
});

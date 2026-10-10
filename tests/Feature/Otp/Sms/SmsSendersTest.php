<?php

declare(strict_types=1);

use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;
use Cbox\Id\Otp\Sms\Senders\ArraySmsSender;
use Cbox\Id\Otp\Sms\Senders\BirdSmsSender;
use Cbox\Id\Otp\Sms\Senders\FortySixElksSmsSender;
use Cbox\Id\Otp\Sms\Senders\LogSmsSender;
use Cbox\Id\Otp\Sms\Senders\MessageBirdSmsSender;
use Cbox\Id\Otp\Sms\Senders\TwilioSmsSender;
use Cbox\Id\Otp\Sms\SmsSenderFactory;
use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Psr\Log\LoggerInterface;

function smsTo(string $number = '+4512345678', string $body = '123456 is your code'): SmsMessage
{
    return new SmsMessage((new PhoneNumberNormaliser)->parse($number), $body);
}

/**
 * @param  array<string, mixed>  $config
 */
function smsDriver(string $driver, array $config = []): SmsSender
{
    config()->set('cbox-id.sms.drivers.'.$driver, $config);

    return app(SmsSenderFactory::class)->make($driver);
}

it('sends through Twilio from a Messaging Service, form-encoded with Basic auth', function (): void {
    Http::fake(['api.twilio.com/*' => Http::response(['sid' => 'SM123'], 201)]);

    $receipt = smsDriver('twilio', [
        'account_sid' => 'AC1', 'auth_token' => 'tok', 'messaging_service_sid' => 'MG1', 'from' => '+4500000000',
    ])->send(smsTo());

    expect($receipt->provider)->toBe('twilio')->and($receipt->messageId)->toBe('SM123');

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.twilio.com/2010-04-01/Accounts/AC1/Messages.json'
        && $request->method() === 'POST'
        && $request->hasHeader('Authorization', 'Basic '.base64_encode('AC1:tok'))
        && $request['To'] === '+4512345678'
        && $request['Body'] === '123456 is your code'
        && $request['MessagingServiceSid'] === 'MG1'
        && ! isset($request['From']));
});

it('sends through Twilio from a number, authenticating with an API key when one is set', function (): void {
    Http::fake(['*' => Http::response(['sid' => 'SM9'], 201)]);

    smsDriver('twilio', [
        'account_sid' => 'AC1', 'api_key' => 'SK1', 'api_secret' => 'sec', 'from' => 'CboxID', 'base_url' => 'https://edge.example.test/',
    ])->send(smsTo());

    Http::assertSent(fn (Request $request): bool => str_starts_with($request->url(), 'https://edge.example.test/2010-04-01/Accounts/AC1/')
        && $request->hasHeader('Authorization', 'Basic '.base64_encode('SK1:sec'))
        && $request['From'] === 'CboxID');
});

it('sends through the MessageBird REST API with the MSISDN unprefixed', function (): void {
    Http::fake(['rest.messagebird.com/*' => Http::response(['id' => 'mb-1'], 201)]);

    $receipt = smsDriver('messagebird', ['access_key' => 'live_x', 'originator' => 'CboxID'])->send(smsTo());

    expect($receipt->messageId)->toBe('mb-1');

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://rest.messagebird.com/messages'
        && $request->hasHeader('Authorization', 'AccessKey live_x')
        && $request['recipients'] === ['4512345678']
        && $request['originator'] === 'CboxID'
        && $request['body'] === '123456 is your code');
});

it('sends through the Bird Channels API', function (): void {
    Http::fake(['api.bird.com/*' => Http::response(['id' => 'bird-1'], 202)]);

    $receipt = smsDriver('bird', ['access_key' => 'k', 'workspace_id' => 'ws 1', 'channel_id' => 'ch1'])->send(smsTo());

    expect($receipt->provider)->toBe('bird')->and($receipt->messageId)->toBe('bird-1');

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.bird.com/workspaces/ws%201/channels/ch1/messages'
        && $request->hasHeader('Authorization', 'AccessKey k')
        && $request['receiver'] === ['contacts' => [['identifierKey' => 'phonenumber', 'identifierValue' => '+4512345678']]]
        && $request['body'] === ['type' => 'text', 'text' => ['text' => '123456 is your code']]);
});

it('sends through 46elks, with a dry run when configured', function (): void {
    Http::fake(['api.46elks.com/*' => Http::response(['id' => 's7e2', 'status' => 'created'])]);

    $receipt = smsDriver('46elks', ['username' => 'u', 'password' => 'p', 'from' => 'CboxID', 'dry_run' => 'true'])->send(smsTo('+46701234567'));

    expect($receipt->provider)->toBe('46elks')->and($receipt->messageId)->toBe('s7e2');

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.46elks.com/a1/sms'
        && $request->hasHeader('Authorization', 'Basic '.base64_encode('u:p'))
        && $request['to'] === '+46701234567'
        && $request['from'] === 'CboxID'
        && $request['message'] === '123456 is your code'
        && $request['dryrun'] === 'yes');
});

it('reports a provider refusal with the status and code, never the number or the body', function (): void {
    Http::fake(['*' => Http::response(['code' => 21211, 'message' => "The 'To' number +4512345678 is not valid."], 400)]);

    try {
        smsDriver('twilio', ['account_sid' => 'AC1', 'auth_token' => 't', 'from' => 'X'])->send(smsTo());
        $this->fail('Expected the refusal to throw.');
    } catch (SmsDeliveryFailed $e) {
        expect($e->getMessage())->toContain('twilio')
            ->and($e->getMessage())->toContain('400')
            ->and($e->getMessage())->toContain('21211')
            ->and($e->getMessage())->not->toContain('4512345678')
            ->and($e->getMessage())->not->toContain('123456');
    }
});

it('drops a 46elks error body, which is free text that can echo the input', function (): void {
    Http::fake(['*' => Http::response('Invalid to number +4512345678', 403)]);

    expect(fn () => smsDriver('46elks', ['username' => 'u', 'password' => 'p', 'from' => 'X'])->send(smsTo()))
        ->toThrow(fn (SmsDeliveryFailed $e) => expect($e->getMessage())->not->toContain('4512345678')->toContain('403'));
});

it('turns a connection failure into an unreachable provider, without retrying', function (): void {
    $attempts = 0;
    Http::fake(['*' => function () use (&$attempts): never {
        $attempts++;

        throw new ConnectionException('timed out');
    }]);

    expect(fn () => smsDriver('bird', ['access_key' => 'k', 'workspace_id' => 'w', 'channel_id' => 'c'])->send(smsTo()))
        ->toThrow(SmsDeliveryFailed::class, 'could not be reached');

    expect($attempts)->toBe(1);
});

it('names the missing setting when a driver is misconfigured', function (string $driver, array $config, string $missing): void {
    expect(fn () => smsDriver($driver, $config))->toThrow(SmsDeliveryFailed::class, $missing);
})->with([
    ['twilio', ['auth_token' => 't', 'from' => 'X'], 'account_sid'],
    ['twilio', ['account_sid' => 'AC', 'from' => 'X'], 'auth_token'],
    ['twilio', ['account_sid' => 'AC', 'auth_token' => 't'], 'from or messaging_service_sid'],
    ['messagebird', ['access_key' => 'k'], 'originator'],
    ['bird', ['access_key' => 'k', 'workspace_id' => 'w'], 'channel_id'],
    ['46elks', ['username' => 'u', 'password' => 'p'], 'from'],
]);

it('builds the shipped drivers by name and refuses an unknown one', function (): void {
    $factory = app(SmsSenderFactory::class);

    expect($factory->make('log'))->toBeInstanceOf(LogSmsSender::class)
        ->and($factory->make('array'))->toBeInstanceOf(ArraySmsSender::class)
        ->and(smsDriver('twilio', ['account_sid' => 'a', 'auth_token' => 'b', 'from' => 'c']))->toBeInstanceOf(TwilioSmsSender::class)
        ->and(smsDriver('messagebird', ['access_key' => 'a', 'originator' => 'b']))->toBeInstanceOf(MessageBirdSmsSender::class)
        ->and(smsDriver('bird', ['access_key' => 'a', 'workspace_id' => 'b', 'channel_id' => 'c']))->toBeInstanceOf(BirdSmsSender::class)
        ->and(smsDriver('46elks', ['username' => 'a', 'password' => 'b', 'from' => 'c']))->toBeInstanceOf(FortySixElksSmsSender::class)
        ->and($factory->make(ArraySmsSender::class))->toBeInstanceOf(ArraySmsSender::class);

    expect(fn () => $factory->make('carrier-pigeon'))->toThrow(SmsDeliveryFailed::class, 'carrier-pigeon');
});

it('binds the configured driver as the sender', function (): void {
    config()->set('cbox-id.sms.driver', 'array');
    app()->forgetInstance(SmsSender::class);

    expect(app(SmsSender::class))->toBeInstanceOf(ArraySmsSender::class);
});

it('logs the message in development and refuses to in production', function (): void {
    $log = Mockery::mock(LoggerInterface::class);
    $log->shouldReceive('warning')->once()->with(Mockery::type('string'), Mockery::on(
        fn (array $context): bool => $context['to'] === '+4512345678' && $context['body'] === '123456 is your code',
    ));

    expect((new LogSmsSender($log, false))->send(smsTo())->provider)->toBe('log');

    $silent = Mockery::mock(LoggerInterface::class);
    $silent->shouldNotReceive('warning');

    expect(fn () => (new LogSmsSender($silent, true))->send(smsTo()))
        ->toThrow(SmsDeliveryFailed::class, 'refused in production');
});

it('keeps messages in memory for tests and can be told to fail once', function (): void {
    $fake = new ArraySmsSender;
    $fake->assertNothingSent();

    $fake->send(smsTo('+4512345678', '424242 is your code'));
    $fake->send(smsTo('+46701234567', '717171 is your code'));

    $fake->assertSentCount(2);
    $fake->assertSent('+4512345678');
    expect($fake->latestCode('+4512345678'))->toBe('424242')
        ->and($fake->latestCode())->toBe('717171')
        ->and($fake->latest('+4799999999'))->toBeNull();

    $fake->failNext();
    expect(fn () => $fake->send(smsTo()))->toThrow(SmsDeliveryFailed::class);
    $fake->send(smsTo());
    $fake->assertSentCount(3);
});

<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Cbox\Id\Otp\Sms\ValueObjects\SmsReceipt;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;

/**
 * What every HTTP provider driver shares: bounded timeouts, NO automatic retries, and
 * failures that name the provider and status but never the number or the body.
 *
 * No retries because a retry after a timeout can deliver the same code twice and bill
 * twice, and because the person waiting can press "resend" — which goes back through the
 * cooldown and the caps, where a silent retry would not.
 *
 * The base URLs are operator configuration (a regional edge, a test double), never
 * request input, so there is no SSRF surface here.
 */
abstract class HttpSmsSender implements SmsSender
{
    public function __construct(
        protected readonly Factory $http,
        protected readonly int $timeoutSeconds = 10,
    ) {}

    final public function send(SmsMessage $message): SmsReceipt
    {
        try {
            $response = $this->dispatch($this->http->timeout($this->timeoutSeconds)->connectTimeout(min(5, $this->timeoutSeconds))->acceptJson(), $message);
        } catch (ConnectionException $e) {
            throw SmsDeliveryFailed::unreachable($this->name(), $e);
        }

        if (! $response->successful()) {
            throw SmsDeliveryFailed::rejected($this->name(), $response->status(), $this->providerErrorCode($response));
        }

        $id = $response->json($this->messageIdKey());

        return new SmsReceipt($this->name(), is_scalar($id) ? (string) $id : null);
    }

    abstract protected function dispatch(PendingRequest $request, SmsMessage $message): Response;

    /** Where the provider puts its message id in a successful response body. */
    abstract protected function messageIdKey(): string;

    /**
     * The provider's own numeric error code, if its error body carries one. Only a short
     * alphanumeric code survives — never free text, which can echo the recipient.
     */
    protected function providerErrorCode(Response $response): ?string
    {
        $code = $response->json('code');

        return is_scalar($code) && preg_match('/^[A-Za-z0-9_.-]{1,32}$/', (string) $code) === 1 ? (string) $code : null;
    }

    protected static function required(string $provider, mixed $value, string $name): string
    {
        if (! is_string($value) || $value === '') {
            throw SmsDeliveryFailed::misconfigured($provider, $name);
        }

        return $value;
    }

    protected static function baseUrl(mixed $configured, string $default): string
    {
        return rtrim(is_string($configured) && $configured !== '' ? $configured : $default, '/');
    }
}

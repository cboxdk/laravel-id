<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;

/**
 * MessageBird's REST API: `POST https://rest.messagebird.com/messages`, JSON,
 * `Authorization: AccessKey …`. For accounts still on the MessageBird platform; accounts
 * migrated to Bird use {@see BirdSmsSender}.
 */
class MessageBirdSmsSender extends HttpSmsSender
{
    private readonly string $accessKey;

    private readonly string $originator;

    private readonly string $baseUrl;

    /**
     * @param  array<string, mixed>  $config  `cbox-id.sms.drivers.messagebird`
     */
    public function __construct(Factory $http, array $config, int $timeoutSeconds = 10)
    {
        parent::__construct($http, $timeoutSeconds);

        $this->accessKey = self::required('messagebird', $config['access_key'] ?? null, 'access_key');
        $this->originator = self::required('messagebird', $config['originator'] ?? null, 'originator');
        $this->baseUrl = self::baseUrl($config['base_url'] ?? null, 'https://rest.messagebird.com');
    }

    public function name(): string
    {
        return 'messagebird';
    }

    protected function dispatch(PendingRequest $request, SmsMessage $message): Response
    {
        return $request->asJson()
            ->withHeaders(['Authorization' => 'AccessKey '.$this->accessKey])
            ->post($this->baseUrl.'/messages', [
                // MessageBird takes MSISDNs without the plus.
                'recipients' => [ltrim($message->to->e164(), '+')],
                'originator' => $this->originator,
                'body' => $message->body,
            ]);
    }

    protected function messageIdKey(): string
    {
        return 'id';
    }

    protected function providerErrorCode(Response $response): ?string
    {
        $code = $response->json('errors.0.code');

        return is_int($code) ? (string) $code : null;
    }
}

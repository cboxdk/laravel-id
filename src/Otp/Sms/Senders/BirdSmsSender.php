<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;

/**
 * Bird (formerly MessageBird) Channels API:
 * `POST https://api.bird.com/workspaces/{workspaceId}/channels/{channelId}/messages`,
 * JSON, `Authorization: AccessKey …`, sent through an SMS channel configured in the Bird
 * workspace (which owns the sender id and its country registrations).
 */
class BirdSmsSender extends HttpSmsSender
{
    private readonly string $accessKey;

    private readonly string $workspaceId;

    private readonly string $channelId;

    private readonly string $baseUrl;

    /**
     * @param  array<string, mixed>  $config  `cbox-id.sms.drivers.bird`
     */
    public function __construct(Factory $http, array $config, int $timeoutSeconds = 10)
    {
        parent::__construct($http, $timeoutSeconds);

        $this->accessKey = self::required('bird', $config['access_key'] ?? null, 'access_key');
        $this->workspaceId = self::required('bird', $config['workspace_id'] ?? null, 'workspace_id');
        $this->channelId = self::required('bird', $config['channel_id'] ?? null, 'channel_id');
        $this->baseUrl = self::baseUrl($config['base_url'] ?? null, 'https://api.bird.com');
    }

    public function name(): string
    {
        return 'bird';
    }

    protected function dispatch(PendingRequest $request, SmsMessage $message): Response
    {
        return $request->asJson()
            ->withHeaders(['Authorization' => 'AccessKey '.$this->accessKey])
            ->post(sprintf(
                '%s/workspaces/%s/channels/%s/messages',
                $this->baseUrl,
                rawurlencode($this->workspaceId),
                rawurlencode($this->channelId),
            ), [
                'receiver' => ['contacts' => [['identifierKey' => 'phonenumber', 'identifierValue' => $message->to->e164()]]],
                'body' => ['type' => 'text', 'text' => ['text' => $message->body]],
            ]);
    }

    protected function messageIdKey(): string
    {
        return 'id';
    }
}

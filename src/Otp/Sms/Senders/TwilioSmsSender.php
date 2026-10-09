<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;

/**
 * Twilio Programmable Messaging: `POST /2010-04-01/Accounts/{AccountSid}/Messages.json`,
 * form-encoded, HTTP Basic with the account SID and auth token (or an API key SID and
 * secret). Sends from a Messaging Service when one is configured — the better choice,
 * because Twilio then picks a sender per destination and applies its own geo-permissions
 * — otherwise from the configured number or alphanumeric sender id.
 *
 * Twilio's Verify product is NOT used: it generates its own codes, which would put code
 * generation, hashing, attempt caps and rate limits outside this platform.
 */
class TwilioSmsSender extends HttpSmsSender
{
    private readonly string $accountSid;

    private readonly string $username;

    private readonly string $password;

    private readonly ?string $from;

    private readonly ?string $messagingServiceSid;

    private readonly string $baseUrl;

    /**
     * @param  array<string, mixed>  $config  `cbox-id.sms.drivers.twilio`
     */
    public function __construct(Factory $http, array $config, int $timeoutSeconds = 10)
    {
        parent::__construct($http, $timeoutSeconds);

        $this->accountSid = self::required('twilio', $config['account_sid'] ?? null, 'account_sid');

        $apiKey = $config['api_key'] ?? null;
        $usesApiKey = is_string($apiKey) && $apiKey !== '';
        $this->username = $usesApiKey ? $apiKey : $this->accountSid;
        $this->password = $usesApiKey
            ? self::required('twilio', $config['api_secret'] ?? null, 'api_secret')
            : self::required('twilio', $config['auth_token'] ?? null, 'auth_token');

        $from = $config['from'] ?? null;
        $service = $config['messaging_service_sid'] ?? null;
        $this->from = is_string($from) && $from !== '' ? $from : null;
        $this->messagingServiceSid = is_string($service) && $service !== '' ? $service : null;

        if ($this->from === null && $this->messagingServiceSid === null) {
            self::required('twilio', null, 'from or messaging_service_sid');
        }

        $this->baseUrl = self::baseUrl($config['base_url'] ?? null, 'https://api.twilio.com');
    }

    public function name(): string
    {
        return 'twilio';
    }

    protected function dispatch(PendingRequest $request, SmsMessage $message): Response
    {
        $form = ['To' => $message->to->e164(), 'Body' => $message->body];

        if ($this->messagingServiceSid !== null) {
            $form['MessagingServiceSid'] = $this->messagingServiceSid;
        } else {
            $form['From'] = (string) $this->from;
        }

        return $request->asForm()
            ->withBasicAuth($this->username, $this->password)
            ->post($this->baseUrl.'/2010-04-01/Accounts/'.rawurlencode($this->accountSid).'/Messages.json', $form);
    }

    protected function messageIdKey(): string
    {
        return 'sid';
    }
}

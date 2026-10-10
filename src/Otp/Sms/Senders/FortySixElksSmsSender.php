<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;

/**
 * 46elks (Swedish, Nordic coverage): `POST https://api.46elks.com/a1/sms`, form-encoded,
 * HTTP Basic with the API username and password. `from` is a number or an alphanumeric
 * sender of up to 11 characters. `dry_run` makes 46elks validate and price the message
 * without sending it — useful for a staging environment pointed at the real API.
 */
class FortySixElksSmsSender extends HttpSmsSender
{
    private readonly string $username;

    private readonly string $password;

    private readonly string $from;

    private readonly bool $dryRun;

    private readonly string $baseUrl;

    /**
     * @param  array<string, mixed>  $config  `cbox-id.sms.drivers.46elks`
     */
    public function __construct(Factory $http, array $config, int $timeoutSeconds = 10)
    {
        parent::__construct($http, $timeoutSeconds);

        $this->username = self::required('46elks', $config['username'] ?? null, 'username');
        $this->password = self::required('46elks', $config['password'] ?? null, 'password');
        $this->from = self::required('46elks', $config['from'] ?? null, 'from');
        $this->dryRun = filter_var($config['dry_run'] ?? false, FILTER_VALIDATE_BOOL);
        $this->baseUrl = self::baseUrl($config['base_url'] ?? null, 'https://api.46elks.com');
    }

    public function name(): string
    {
        return '46elks';
    }

    protected function dispatch(PendingRequest $request, SmsMessage $message): Response
    {
        $form = ['from' => $this->from, 'to' => $message->to->e164(), 'message' => $message->body];

        if ($this->dryRun) {
            $form['dryrun'] = 'yes';
        }

        return $request->asForm()
            ->withBasicAuth($this->username, $this->password)
            ->post($this->baseUrl.'/a1/sms', $form);
    }

    protected function messageIdKey(): string
    {
        return 'id';
    }

    /** 46elks answers errors in plain text, which can echo the input — keep none of it. */
    protected function providerErrorCode(Response $response): ?string
    {
        return null;
    }
}

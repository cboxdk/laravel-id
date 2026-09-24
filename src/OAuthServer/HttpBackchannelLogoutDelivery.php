<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\OAuthServer\Contracts\BackchannelLogoutDelivery;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\LogoutTokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\UnsafeBackchannelLogoutUri;
use Cbox\Id\OAuthServer\Support\SafeBackchannelLogoutUrl;
use Cbox\Id\OAuthServer\ValueObjects\LogoutDeliveryOutcome;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

/**
 * Back-Channel Logout 1.0 §2.5: `POST` the logout token to the relying party's
 * `backchannel_logout_uri` as `application/x-www-form-urlencoded` (`logout_token=…`).
 *
 * The client is read FRESH, at delivery. A client deleted, or one that removed its URI,
 * between the sign-out and the worker picking the job up is not called; a URI changed in
 * that window is called at its new value, which is the one its owner now answers.
 *
 * Timeouts are short because nothing waits on the answer except this worker, and a
 * relying party that takes longer than a few seconds to end a session is one that is
 * struggling — the retry is kinder to it than a held connection.
 */
class HttpBackchannelLogoutDelivery implements BackchannelLogoutDelivery
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly LogoutTokenIssuer $tokens,
    ) {}

    public function deliver(LogoutNotice $notice): LogoutDeliveryOutcome
    {
        $client = $this->clients->byClientId($notice->clientId);
        $uri = $client?->backchannel_logout_uri;

        if ($client === null || $uri === null || $uri === '') {
            return LogoutDeliveryOutcome::skipped('the client no longer has a backchannel_logout_uri');
        }

        // §2.2: a relying party that registered `backchannel_logout_session_required`
        // needs `sid` to find the session. A subject-only token would be rejected — or
        // worse, accepted as "every session" by an RP that asked to be told which one.
        if ($client->backchannel_logout_session_required && $notice->sid === null) {
            return LogoutDeliveryOutcome::rejected('the client requires sid and this logout has no session to name');
        }

        try {
            // The SSRF gate, and the connection pinned to what it checked. A refusal is
            // final: the address will not become public by trying again in a minute.
            $pinned = SafeBackchannelLogoutUrl::pinnedOptions($uri);
        } catch (UnsafeBackchannelLogoutUri $e) {
            return LogoutDeliveryOutcome::rejected($e->getMessage());
        }

        $token = $this->tokens->issue($client, $notice);

        try {
            $response = Http::withOptions($pinned)
                ->connectTimeout($this->seconds('connect_timeout', 3))
                ->timeout($this->seconds('timeout', 5))
                ->asForm()
                // §2.5 requires the RP to answer with no-store; asking the same of every
                // cache between us costs nothing.
                ->withHeaders(['Cache-Control' => 'no-cache, no-store'])
                ->post($uri, ['logout_token' => $token]);
        } catch (ConnectionException $e) {
            return LogoutDeliveryOutcome::retry('connection failed: '.$e->getMessage());
        }

        $status = $response->status();

        // §2.8: 200 on success — "however, note that some Web frameworks will substitute
        // 204 No Content". Any 2xx is a relying party saying it is done.
        if ($status >= 200 && $status < 300) {
            return LogoutDeliveryOutcome::delivered($status);
        }

        // Timeouts, throttling and server errors are the RP's bad minute, not a verdict.
        if ($status >= 500 || $status === 408 || $status === 429) {
            return LogoutDeliveryOutcome::retry("HTTP {$status}", $status);
        }

        // Anything else — a 400 is what §2.8 says an RP returns for a token it refused, and
        // a redirect is refused because we never follow one — will answer the same again.
        // The RP's `error` is kept for the operator, bounded: it is the RP's text, not ours.
        $error = $response->json('error');
        $detail = is_string($error) && $error !== '' ? ': '.Str::limit($error, 200) : '';

        return LogoutDeliveryOutcome::rejected("HTTP {$status}{$detail}", $status);
    }

    private function seconds(string $key, int $default): int
    {
        $value = config("cbox-id.oauth.backchannel_logout.{$key}", $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}

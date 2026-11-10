<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Jobs;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\BackchannelTokenDeliveryMode;
use Cbox\Id\OAuthServer\Exceptions\UnsafeCibaNotificationEndpoint;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Support\SafeCibaNotificationUrl;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * CIBA Core §10.2: POST `{"auth_req_id": "…"}` to the client's
 * `backchannel_client_notification_endpoint`, with `Authorization: Bearer
 * <client_notification_token>`. The client then calls the token endpoint once.
 *
 * Shaped like {@see DeliverBackchannelLogout}: re-enters the environment the request lives
 * in, reads the client FRESH (an endpoint removed since is not called; one changed is
 * called at its new value), releases rather than throws between attempts so the `sync`
 * driver never turns Approve into an error page, and audits the final outcome.
 *
 * Short backoff, because a CIBA request lives minutes, not hours; a client that missed
 * every ping can still poll. The secrets are cleared on any final outcome.
 */
class NotifyCibaClient implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    /** Seconds before attempt 2, 3, … — the last value repeats. */
    private const BACKOFF = [2, 5, 15, 30];

    public int $tries;

    public int $timeout = 20;

    public function __construct(
        public readonly string $environmentId,
        public readonly string $requestId,
    ) {
        $this->tries = self::maxAttempts();
    }

    public static function maxAttempts(): int
    {
        $configured = config('cbox-id.oauth.ciba.ping.max_attempts', 5);

        return max(1, is_numeric($configured) ? (int) $configured : 5);
    }

    public function handle(EnvironmentContext $context, ClientRegistry $clients, AuditLog $audit): void
    {
        $context->runAs(GenericEnvironment::of($this->environmentId), function () use ($clients, $audit): void {
            $this->deliver($clients, $audit);
        });
    }

    /**
     * @return list<int>
     */
    public function backoff(): array
    {
        return self::BACKOFF;
    }

    /** The queue gave up on its own (worker died, timed out on the last try). */
    public function failed(?Throwable $exception): void
    {
        app(EnvironmentContext::class)->runAs(GenericEnvironment::of($this->environmentId), function () use ($exception): void {
            $request = BackchannelAuthRequest::query()->whereKey($this->requestId)->first();

            if ($request !== null && $request->getRawOriginal('client_notification_token') !== null) {
                $this->finish(app(AuditLog::class), $request, 'oauth.ciba.notification_failed', null, $exception?->getMessage() ?? 'the queue gave up on the delivery');
            }
        });
    }

    private function deliver(ClientRegistry $clients, AuditLog $audit): void
    {
        $request = BackchannelAuthRequest::query()->whereKey($this->requestId)->first();
        $token = $request?->client_notification_token;
        $authReqId = $request?->notification_auth_req_id;

        // Redeemed already (the client polled first), or never a ping-mode request.
        if ($request === null || $token === null || $authReqId === null) {
            return;
        }

        $client = $clients->byClientId($request->client_id);
        $endpoint = $client?->backchannel_client_notification_endpoint;

        if ($client === null || $client->backchannelTokenDeliveryMode() !== BackchannelTokenDeliveryMode::Ping || $endpoint === null || $endpoint === '') {
            $this->finish($audit, $request, 'oauth.ciba.notification_failed', null, 'the client no longer has a ping notification endpoint');

            return;
        }

        try {
            $pinned = SafeCibaNotificationUrl::pinnedOptions($endpoint);
        } catch (UnsafeCibaNotificationEndpoint $e) {
            $this->finish($audit, $request, 'oauth.ciba.notification_failed', null, $e->getMessage());

            return;
        }

        try {
            $response = Http::withOptions($pinned)
                ->connectTimeout($this->seconds('connect_timeout', 3))
                ->timeout($this->seconds('timeout', 5))
                ->withToken($token)
                ->acceptJson()
                ->asJson()
                ->post($endpoint, ['auth_req_id' => $authReqId]);
        } catch (ConnectionException $e) {
            $this->retryOrGiveUp($audit, $request, null, 'connection failed: '.$e->getMessage());

            return;
        }

        $status = $response->status();

        if ($status >= 200 && $status < 300) {
            $this->finish($audit, $request, 'oauth.ciba.notified', $status, '');

            return;
        }

        if ($status >= 500 || $status === 408 || $status === 429) {
            $this->retryOrGiveUp($audit, $request, $status, "HTTP {$status}");

            return;
        }

        // A 4xx (or a redirect, which is never followed) will answer the same again.
        $this->finish($audit, $request, 'oauth.ciba.notification_failed', $status, "HTTP {$status}");
    }

    private function retryOrGiveUp(AuditLog $audit, BackchannelAuthRequest $request, ?int $status, string $reason): void
    {
        $attempt = $this->attempts();

        if ($attempt >= self::maxAttempts()) {
            $this->finish($audit, $request, 'oauth.ciba.notification_failed', $status, $reason);

            return;
        }

        Log::warning('cbox-id: CIBA ping failed; will retry', [
            'environment_id' => $this->environmentId,
            'client_id' => $request->client_id,
            'request_id' => $request->id,
            'reason' => $reason,
            'attempt' => $attempt,
        ]);

        $this->release(self::BACKOFF[min($attempt - 1, count(self::BACKOFF) - 1)]);
    }

    /** A final outcome: the secrets are dropped and the outcome is on the audit trail. */
    private function finish(AuditLog $audit, BackchannelAuthRequest $request, string $action, ?int $status, string $reason): void
    {
        $request->forceFill(['client_notification_token' => null, 'notification_auth_req_id' => null])->save();

        if ($action !== 'oauth.ciba.notified') {
            Log::warning('cbox-id: CIBA ping failed; giving up', [
                'environment_id' => $this->environmentId,
                'client_id' => $request->client_id,
                'request_id' => $request->id,
                'reason' => $reason,
            ]);
        }

        $audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            targetType: 'ciba_request',
            targetId: $request->id,
            context: array_filter([
                'client_id' => $request->client_id,
                'attempts' => $this->attempts(),
                'http_status' => $status,
                'reason' => $reason !== '' ? $reason : null,
            ], static fn (mixed $value): bool => $value !== null),
        ));
    }

    private function seconds(string $key, int $default): int
    {
        $value = config("cbox-id.oauth.ciba.ping.{$key}", $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}

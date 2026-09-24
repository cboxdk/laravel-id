<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Jobs;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\OAuthServer\Contracts\BackchannelLogoutDelivery;
use Cbox\Id\OAuthServer\Enums\LogoutDeliveryStatus;
use Cbox\Id\OAuthServer\Exceptions\BackchannelLogoutGaveUp;
use Cbox\Id\OAuthServer\ValueObjects\LogoutDeliveryOutcome;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;
use Cbox\Id\Webhooks\Jobs\DeliverWebhook;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Delivers ONE logout token to ONE relying party, off the sign-out request.
 *
 * RETRIES ARE RELEASES, NOT EXCEPTIONS. A failed attempt releases the job back onto the
 * queue with a growing delay; the last one records the failure and stops. Throwing
 * instead would work on a real worker and break sign-out on the `sync` driver, where a
 * job runs inside the request that queued it: one relying party returning 500 would have
 * turned somebody's "sign out" into an error page. Released on `sync`, the attempt is
 * simply not retried.
 *
 * ENVIRONMENT, AS {@see DeliverWebhook} DOES IT. A worker carries no ambient environment,
 * and everything this job touches is environment-owned — the client row, the signing key,
 * the issuer the token names — so it re-enters exactly the environment the logout
 * happened in before doing anything.
 *
 * Every final outcome is audited on the environment's trail — `oauth.backchannel_logout.
 * delivered` or `.failed`, with the reason — because "the app did not sign me out" is a
 * support question, and the answer must be findable without a debugger. Each failed
 * attempt is also logged, so a relying party that is flapping is visible before it gives up.
 */
class DeliverBackchannelLogout implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    /** Seconds to wait before attempt 2, 3, … — the last value repeats. */
    private const BACKOFF = [10, 60, 300, 900];

    /** The worker's own ceiling; kept in step with {@see maxAttempts()}. */
    public int $tries;

    /** No attempt may hold a worker longer than this; the HTTP timeouts are far below it. */
    public int $timeout = 30;

    public function __construct(
        public readonly string $environmentId,
        public readonly string $clientId,
        public readonly ?string $subject,
        public readonly ?string $sid,
    ) {
        $this->tries = self::maxAttempts();
    }

    public static function maxAttempts(): int
    {
        $configured = config('cbox-id.oauth.backchannel_logout.max_attempts', 5);

        return max(1, is_numeric($configured) ? (int) $configured : 5);
    }

    public function handle(EnvironmentContext $context, BackchannelLogoutDelivery $delivery, AuditLog $audit): void
    {
        $context->runAs(GenericEnvironment::of($this->environmentId), function () use ($delivery, $audit): void {
            $outcome = $delivery->deliver(new LogoutNotice($this->clientId, $this->subject, $this->sid));

            match ($outcome->status) {
                LogoutDeliveryStatus::Delivered => $this->record($audit, 'oauth.backchannel_logout.delivered', $outcome),
                LogoutDeliveryStatus::Skipped => null,
                LogoutDeliveryStatus::Rejected => $this->giveUp($audit, $outcome),
                LogoutDeliveryStatus::Retry => $this->retryOrGiveUp($audit, $outcome),
            };
        });
    }

    /**
     * The queue gave up on its own — the worker died, the job timed out on its last try.
     * Recorded the same way as a failure this job decided, so nothing fails silently.
     */
    public function failed(?Throwable $exception): void
    {
        $context = app(EnvironmentContext::class);
        $audit = app(AuditLog::class);

        // A failure this job already recorded arrives here too (fail() calls back into
        // failed()); it is not recorded twice.
        if ($exception instanceof BackchannelLogoutGaveUp) {
            return;
        }

        $context->runAs(GenericEnvironment::of($this->environmentId), function () use ($audit, $exception): void {
            $this->record($audit, 'oauth.backchannel_logout.failed', LogoutDeliveryOutcome::rejected(
                $exception !== null ? $exception->getMessage() : 'the queue gave up on the delivery',
            ));
        });
    }

    /**
     * @return list<int>
     */
    public function backoff(): array
    {
        return self::BACKOFF;
    }

    private function retryOrGiveUp(AuditLog $audit, LogoutDeliveryOutcome $outcome): void
    {
        $attempt = $this->attempts();

        if ($attempt >= self::maxAttempts()) {
            $this->giveUp($audit, $outcome);

            return;
        }

        Log::warning('cbox-id: back-channel logout delivery failed; will retry', $this->logContext($outcome) + [
            'attempt' => $attempt,
        ]);

        $this->release(self::BACKOFF[min($attempt - 1, count(self::BACKOFF) - 1)]);
    }

    private function giveUp(AuditLog $audit, LogoutDeliveryOutcome $outcome): void
    {
        Log::warning('cbox-id: back-channel logout delivery failed; giving up', $this->logContext($outcome) + [
            'attempt' => $this->attempts(),
        ]);

        $this->record($audit, 'oauth.backchannel_logout.failed', $outcome);

        $this->fail(new BackchannelLogoutGaveUp($outcome->reason));
    }

    private function record(AuditLog $audit, string $action, LogoutDeliveryOutcome $outcome): void
    {
        $audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            targetType: $this->subject !== null ? 'user' : 'session',
            targetId: $this->subject ?? $this->sid,
            context: array_filter([
                'client_id' => $this->clientId,
                'sid' => $this->sid,
                'attempts' => $this->attempts(),
                'http_status' => $outcome->httpStatus,
                'reason' => $outcome->reason !== '' ? $outcome->reason : null,
            ], static fn (mixed $value): bool => $value !== null),
        ));
    }

    /**
     * @return array<string, mixed>
     */
    private function logContext(LogoutDeliveryOutcome $outcome): array
    {
        return [
            'environment_id' => $this->environmentId,
            'client_id' => $this->clientId,
            'reason' => $outcome->reason,
            'http_status' => $outcome->httpStatus,
        ];
    }
}

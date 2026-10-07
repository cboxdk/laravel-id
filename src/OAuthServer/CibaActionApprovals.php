<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\OAuthServer\Contracts\ActionApprovals;
use Cbox\Id\OAuthServer\Enums\ActionApprovalStatus;
use Cbox\Id\OAuthServer\Enums\GrantPollStatus;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ActionApprovalRequest;
use DateTimeImmutable;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * {@see ActionApprovals} on the CIBA request store.
 *
 * The row is an ordinary CIBA request with `purpose = action` and an `action_digest`, so
 * every surface that lists and answers CIBA requests answers these too. Its `auth_req_id`
 * is random and never returned: nothing outside the host can poll it, and
 * {@see CibaAuthenticationService::redeem()} refuses any row with a digest.
 */
class CibaActionApprovals implements ActionApprovals
{
    public const string PURPOSE = 'action';

    private const int DEFAULT_TTL_SECONDS = 300;

    private const int MAX_TTL_SECONDS = 900;

    private const int BINDING_MESSAGE_MAX = 255;

    public function __construct(private readonly EventBus $events) {}

    public function request(Client $client, string $subjectId, string $bindingMessage, string $actionDigest, ?int $ttlSeconds = null): ActionApprovalRequest
    {
        if ($bindingMessage === '' || mb_strlen($bindingMessage) > self::BINDING_MESSAGE_MAX) {
            throw new InvalidArgumentException('A binding message is required and must be at most '.self::BINDING_MESSAGE_MAX.' characters.');
        }

        if (preg_match('/^[a-f0-9]{64}$/', $actionDigest) !== 1) {
            throw new InvalidArgumentException('The action digest must be a lowercase hex SHA-256.');
        }

        $ttl = max(30, min($ttlSeconds ?? $this->configuredTtl(), self::MAX_TTL_SECONDS));
        $interval = $this->pollInterval();

        $model = BackchannelAuthRequest::query()->create([
            'auth_req_id_hash' => hash('sha256', 'action_'.bin2hex(random_bytes(32))),
            'client_id' => $client->client_id,
            'user_id' => $subjectId,
            'scopes' => [],
            'binding_message' => $bindingMessage,
            'status' => GrantPollStatus::Pending,
            'interval' => $interval,
            'expires_at' => now()->addSeconds($ttl),
            'purpose' => self::PURPOSE,
            'action_digest' => $actionDigest,
        ]);

        $this->events->emit(new DomainEvent(
            'oauth.backchannel_authentication_requested',
            [
                'request_id' => $model->id,
                'client_id' => $client->client_id,
                'user_id' => $subjectId,
                'binding_message' => $bindingMessage,
                'scopes' => [],
                'purpose' => self::PURPOSE,
            ],
        ));

        return new ActionApprovalRequest(
            requestId: $model->id,
            subjectId: $subjectId,
            bindingMessage: $bindingMessage,
            expiresAt: DateTimeImmutable::createFromInterface($model->expires_at),
            interval: $interval,
        );
    }

    public function status(string $requestId): ?ActionApprovalStatus
    {
        $record = $this->find($requestId);

        if ($record === null) {
            return null;
        }

        return match (true) {
            $record->consumed_at !== null => ActionApprovalStatus::Consumed,
            $record->status === GrantPollStatus::Denied => ActionApprovalStatus::Denied,
            $record->expires_at->isPast() => ActionApprovalStatus::Expired,
            $record->status === GrantPollStatus::Approved => ActionApprovalStatus::Approved,
            default => ActionApprovalStatus::Pending,
        };
    }

    public function consume(string $requestId, string $actionDigest): bool
    {
        return DB::transaction(function () use ($requestId, $actionDigest): bool {
            $updated = BackchannelAuthRequest::query()
                ->whereKey($requestId)
                ->where('purpose', self::PURPOSE)
                ->where('action_digest', $actionDigest)
                ->where('status', GrantPollStatus::Approved)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())
                ->update(['status' => GrantPollStatus::Redeemed, 'consumed_at' => now()]);

            return $updated === 1;
        });
    }

    private function find(string $requestId): ?BackchannelAuthRequest
    {
        return BackchannelAuthRequest::query()
            ->whereKey($requestId)
            ->where('purpose', self::PURPOSE)
            ->first();
    }

    private function configuredTtl(): int
    {
        $configured = config('cbox-id.oauth.ciba.ttl_seconds', self::DEFAULT_TTL_SECONDS);

        return is_numeric($configured) && (int) $configured > 0 ? (int) $configured : self::DEFAULT_TTL_SECONDS;
    }

    private function pollInterval(): int
    {
        $configured = config('cbox-id.oauth.ciba.poll_interval', 5);

        return is_numeric($configured) && (int) $configured > 0 ? (int) $configured : 5;
    }
}

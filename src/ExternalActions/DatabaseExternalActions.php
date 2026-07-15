<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\ActionEndpointStatus;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\UnsafeActionUrl;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\RegisteredActionEndpoint;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * Database-backed {@see ExternalActions}. Registration SSRF-guards the URL and mints
 * a reveal-once 256-bit signing secret sealed at rest (SecretBox, bound to the row).
 * Everything is environment-owned and audited.
 */
final class DatabaseExternalActions implements ExternalActions
{
    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly UrlGuard $ssrf,
        private readonly EnvironmentContext $environments,
        private readonly AuditLog $audit,
    ) {}

    public function register(HookPoint $hookPoint, string $url, ?string $organizationId = null): RegisteredActionEndpoint
    {
        $this->environments->requireEnvironment();
        $this->assertSafeUrl($url);

        $secret = bin2hex(random_bytes(32));

        $endpoint = new ExternalActionEndpoint;
        $endpoint->id = (string) Str::ulid();
        $endpoint->fill([
            'organization_id' => $organizationId,
            'hook_point' => $hookPoint,
            'url' => $url,
            'status' => ActionEndpointStatus::Active,
        ]);
        $endpoint->secret_encrypted = $this->secretBox->seal($secret, $endpoint->secretContext());
        $endpoint->save();

        $this->audit->record(new AuditEvent(
            action: 'external_action.registered',
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: 'external_action_endpoint',
            targetId: $endpoint->id,
            context: ['hook' => $hookPoint->value, 'url' => $url],
        ));

        return new RegisteredActionEndpoint($endpoint, $secret);
    }

    public function pause(string $endpointId): void
    {
        ExternalActionEndpoint::query()->whereKey($endpointId)->first()
            ?->update(['status' => ActionEndpointStatus::Paused]);
    }

    public function activate(string $endpointId): void
    {
        ExternalActionEndpoint::query()->whereKey($endpointId)->first()
            ?->update(['status' => ActionEndpointStatus::Active]);
    }

    public function remove(string $endpointId): void
    {
        ExternalActionEndpoint::query()->whereKey($endpointId)->delete();
    }

    public function active(HookPoint $hookPoint): Collection
    {
        return ExternalActionEndpoint::query()
            ->where('hook_point', $hookPoint->value)
            ->where('status', ActionEndpointStatus::Active->value)
            ->orderBy('created_at')
            ->get();
    }

    /**
     * @throws UnsafeActionUrl
     */
    private function assertSafeUrl(string $url): void
    {
        if (config('cbox-id.external_actions.verify_url', true) !== true) {
            return;
        }

        try {
            $this->ssrf->assertSafe($url);
        } catch (BlockedUrl) {
            throw UnsafeActionUrl::forUrl($url);
        }
    }
}

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
class DatabaseExternalActions implements ExternalActions
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

    public function pause(string $endpointId, ?string $organizationId): void
    {
        $this->owned($endpointId, $organizationId)?->update(['status' => ActionEndpointStatus::Paused]);
    }

    public function activate(string $endpointId, ?string $organizationId): void
    {
        $this->owned($endpointId, $organizationId)?->update(['status' => ActionEndpointStatus::Active]);
    }

    public function remove(string $endpointId, ?string $organizationId): void
    {
        $this->owned($endpointId, $organizationId)?->delete();
    }

    public function active(HookPoint $hookPoint, ?string $organizationId): Collection
    {
        return ExternalActionEndpoint::query()
            ->where('hook_point', $hookPoint->value)
            ->where('status', ActionEndpointStatus::Active->value)
            // A hook sees only the org it belongs to. Environment-level hooks
            // (organization_id null) are the operator's own policy and DO apply to every
            // org — that is their purpose — but a tenant's hook must never fire for
            // another tenant, or it receives that tenant's subject/claims on every token
            // and its veto denies issuance environment-wide.
            ->where(fn ($query) => $organizationId === null
                ? $query->whereNull('organization_id')
                : $query->whereNull('organization_id')->orWhere('organization_id', $organizationId))
            ->orderBy('created_at')
            ->get();
    }

    /**
     * The endpoint as owned by exactly this organization — an EXACT match, not the
     * "or environment-wide" form used for firing. A tenant admin may manage only their
     * own hooks; the environment's own (organization_id null) hooks are the operator's
     * and stay read-only to tenants, so their ids being listable is harmless.
     */
    private function owned(string $endpointId, ?string $organizationId): ?ExternalActionEndpoint
    {
        return ExternalActionEndpoint::query()
            ->whereKey($endpointId)
            ->where(fn ($query) => $organizationId === null
                ? $query->whereNull('organization_id')
                : $query->where('organization_id', $organizationId))
            ->first();
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

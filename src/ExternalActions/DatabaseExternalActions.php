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
use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\JwtTokenIssuer;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Database-backed {@see ExternalActions}. Registration SSRF-guards the URL and mints
 * a reveal-once 256-bit signing secret sealed at rest (SecretBox, bound to the row).
 * Everything is environment-owned and audited.
 */
class DatabaseExternalActions implements ExternalActions
{
    // Lazy per-call resolution of the ambient environment. This class is a `singleton`
    // (ExternalActionsServiceProvider) and EnvironmentContext is `scoped`, so injecting
    // it here captured the first job's environment for the life of a queue worker.
    use ResolvesEnvironment;

    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly UrlGuard $ssrf,
        private readonly AuditLog $audit,
    ) {}

    public function register(HookPoint $hookPoint, string $url, string $organizationId): RegisteredActionEndpoint
    {
        return $this->store($hookPoint, $url, $organizationId);
    }

    public function registerForEnvironment(HookPoint $hookPoint, string $url): RegisteredActionEndpoint
    {
        return $this->store($hookPoint, $url, null);
    }

    private function store(HookPoint $hookPoint, string $url, ?string $organizationId): RegisteredActionEndpoint
    {
        $this->environments()->requireEnvironment();
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

    /**
     * The active endpoints for a hook point, CACHED per (environment, hook point).
     *
     * This runs on EVERY token mint — {@see JwtTokenIssuer} calls
     * the TokenMinting hook unconditionally, because "a hook point with no actions is
     * a cheap allow". It was not cheap: it was an uncached query on the hot path even
     * in the overwhelmingly common case where an environment has registered no hooks
     * at all.
     *
     * The whole environment's set for the hook point is cached in ONE entry and the
     * per-org narrowing is applied in memory. That is deliberate: an environment-level
     * endpoint (`organization_id` null) participates in EVERY organization's active
     * set, so a per-org cache key could not be invalidated without enumerating every
     * organization. Keyed by (environment, hook point), a changed endpoint invalidates
     * exactly one key — and knows both values itself, so the model's own events can do
     * it (see {@see ExternalActionEndpoint::booted()}).
     *
     * The cached rows carry `secret_encrypted`, which is SecretBox-sealed and is
     * opened only at send time with a key that is not in the cache — so the cache
     * holds no more plaintext than the database does.
     */
    public function active(HookPoint $hookPoint, ?string $organizationId): Collection
    {
        $ttl = $this->cacheTtl();

        $all = $ttl > 0
            ? Cache::remember(
                ExternalActionEndpoint::cacheKey($this->environmentKey(), $hookPoint),
                $ttl,
                fn (): array => $this->activeForEnvironment($hookPoint),
            )
            : $this->activeForEnvironment($hookPoint);

        // A hook sees only the org it belongs to. Environment-level hooks
        // (organization_id null) are the operator's own policy and DO apply to every
        // org — that is their purpose — but a tenant's hook must never fire for
        // another tenant, or it receives that tenant's subject/claims on every token
        // and its veto denies issuance environment-wide.
        return (new Collection($all))
            ->filter(static fn (ExternalActionEndpoint $endpoint): bool => $endpoint->organization_id === null
                || ($organizationId !== null && $endpoint->organization_id === $organizationId))
            ->values();
    }

    /**
     * @return array<int, ExternalActionEndpoint>
     */
    private function activeForEnvironment(HookPoint $hookPoint): array
    {
        return ExternalActionEndpoint::query()
            ->where('hook_point', $hookPoint->value)
            ->where('status', ActionEndpointStatus::Active->value)
            ->orderBy('created_at')
            ->get()
            ->all();
    }

    /**
     * The environment this lookup belongs to, resolved LAZILY through the container.
     *
     * This class is a `singleton` while `EnvironmentContext` is `scoped`, so the
     * injected copy is not safe to build a CACHE KEY from: a queue worker's
     * `forgetScopedInstances()` unsets the binding without resetting this object, and
     * a captured context would key one environment's hooks under another's — the exact
     * bug already fixed in DatabaseKeyManager, DatabaseAuditLog and DatabaseEventBus.
     */
    private function environmentKey(): string
    {
        return $this->environments()->current()?->environmentKey() ?? 'global';
    }

    private function cacheTtl(): int
    {
        $ttl = config('cbox-id.external_actions.cache_ttl', 60);

        return is_numeric($ttl) ? (int) $ttl : 60;
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
        if (! UrlVerification::enforced('cbox-id.external_actions.verify_url')) {
            return;
        }

        try {
            $this->ssrf->assertSafe($url);
        } catch (BlockedUrl) {
            throw UnsafeActionUrl::forUrl($url);
        }
    }
}

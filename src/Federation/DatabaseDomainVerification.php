<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\DnsResolver;
use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Exceptions\DomainAlreadyClaimed;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\VerifiedDomain;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;

/**
 * Database + DNS-backed domain verification. Lookups run under the environment
 * scope (the model is environment-owned), so a domain verified in one environment
 * never routes a login in another.
 */
class DatabaseDomainVerification implements DomainVerification
{
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly Connections $connections,
        private readonly AuditLog $audit,
    ) {}

    public function add(string $organizationId, string $domain): VerifiedDomain
    {
        $normalized = $this->normalize($domain);

        $existing = VerifiedDomain::query()->where('domain', $normalized)->first();

        if ($existing !== null) {
            if ($existing->organization_id !== $organizationId) {
                throw DomainAlreadyClaimed::make($normalized);
            }

            return $existing;
        }

        $verifiedDomain = VerifiedDomain::query()->create([
            'organization_id' => $organizationId,
            'domain' => $normalized,
            'verification_token' => bin2hex(random_bytes(16)),
            'verified_at' => null,
            'capture' => false,
        ]);

        $this->record('domain.added', $verifiedDomain, ['domain' => $normalized]);

        return $verifiedDomain;
    }

    public function verify(string $id): bool
    {
        $domain = VerifiedDomain::query()->whereKey($id)->firstOrFail();

        if ($domain->isVerified()) {
            return true;
        }

        $records = array_map('trim', $this->dns->txtRecords($this->challengeHost($domain->domain)));

        if (! in_array($domain->verification_token, $records, true)) {
            return false;
        }

        $domain->forceFill(['verified_at' => now()])->save();
        $this->record('domain.verified', $domain, ['domain' => $domain->domain]);

        return true;
    }

    public function setCapture(string $id, bool $capture): void
    {
        $domain = VerifiedDomain::query()->whereKey($id)->firstOrFail();
        $domain->forceFill(['capture' => $capture])->save();

        $this->record($capture ? 'domain.capture_enabled' : 'domain.capture_disabled', $domain, [
            'domain' => $domain->domain,
        ]);
    }

    public function remove(string $id): void
    {
        $domain = VerifiedDomain::query()->whereKey($id)->first();

        if ($domain === null) {
            return;
        }

        $domain->delete();
        $this->record('domain.removed', $domain, ['domain' => $domain->domain]);
    }

    public function forOrganization(string $organizationId): array
    {
        return array_values(
            VerifiedDomain::query()
                ->where('organization_id', $organizationId)
                ->orderBy('domain')
                ->get()
                ->all()
        );
    }

    public function forEmail(string $email): ?VerifiedDomain
    {
        $domain = $this->domainOf($email);

        if ($domain === null) {
            return null;
        }

        return VerifiedDomain::query()
            ->where('domain', $domain)
            ->whereNotNull('verified_at')
            ->first();
    }

    public function connectionForEmail(string $email): ?Connection
    {
        $verified = $this->forEmail($email);

        if ($verified === null) {
            return null;
        }

        $connection = $this->connections->forOrganization($verified->organization_id);

        return $connection !== null && $connection->isActive() ? $connection : null;
    }

    public function challengeHost(string $domain): string
    {
        return '_cbox-id-challenge.'.$this->normalize($domain);
    }

    private function domainOf(string $email): ?string
    {
        $at = strrpos($email, '@');

        if ($at === false) {
            return null;
        }

        $domain = $this->normalize(substr($email, $at + 1));

        return $domain !== '' ? $domain : null;
    }

    private function normalize(string $domain): string
    {
        return ltrim(strtolower(trim($domain)), '@');
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function record(string $action, VerifiedDomain $domain, array $context): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::User,
            organizationId: $domain->organization_id,
            targetType: 'verified_domain',
            targetId: $domain->id,
            context: $context,
        ));
    }
}

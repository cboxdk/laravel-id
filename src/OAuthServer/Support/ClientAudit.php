<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\OAuthServer\Models\Client;

/**
 * The one shape an app's lifecycle takes in the audit trail.
 *
 * Recorded HERE, in the framework, rather than by each console: an app's creation, its
 * secret rotations and its deletion are the changes somebody asks about after an incident,
 * and a trail that exists only when the console that made the change remembered to write
 * it is a trail with holes exactly where nobody looked. Every caller of the registry — the
 * environment console, the tenant console, the management API, RFC 7592 self-management,
 * an artisan command — gets the same entries for free.
 *
 * An app an organization owns is recorded on that organization's trail, so the tenant
 * can see it; a platform-owned app on the system trail. The target is the public
 * `client_id`, the identifier every other entry about the app already uses.
 */
class ClientAudit
{
    public const CREATED = 'app.created';

    public const UPDATED = 'app.updated';

    public const SECRET_ROTATED = 'app.secret_rotated';

    public const SECRET_REVOKED = 'app.secret_revoked';

    public const DELETED = 'app.deleted';

    /**
     * @param  array<string, mixed>  $context
     */
    public function record(string $action, Client $client, ?AuditActor $actor, array $context = []): void
    {
        $actor ??= AuditActor::system();

        // Resolved per call, not injected: the registry is a singleton, and a captured log
        // would outlive a host's (or a test's) swap of the binding.
        app(AuditLog::class)->record(new AuditEvent(
            action: $action,
            actorType: $actor->type,
            actorId: $actor->id,
            organizationId: $client->organization_id,
            targetType: 'client',
            targetId: $client->client_id,
            context: ['name' => $client->name] + $context,
        ));
    }
}

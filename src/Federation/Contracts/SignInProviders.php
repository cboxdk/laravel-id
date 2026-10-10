<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;

/**
 * The social sign-in buttons — catalogue providers such as Google and GitHub — and how an
 * organization inherits them from its environment.
 *
 * TWO OWNERS. A catalogue connection belongs to the ENVIRONMENT (`organization_id` null)
 * or to one ORGANIZATION. The environment's are what "turn on Google for my app" means: one
 * set of credentials, offered on every sign-in page in the environment. An organization's
 * are its own credentials with a provider, offered on its own page.
 *
 * THE PRECEDENCE, for provider key K on organization O's sign-in page — first match wins:
 *
 *  1. O has its OWN K connection, active or turned off. O's decides: it is offered when it
 *     is active and not at all when it is turned off. An organization that set up its own
 *     Google meant its own Google; falling back to the environment's credentials because its
 *     own were switched off would put its people's accounts on the wrong side of a line it
 *     drew. (A draft — a form saved half-way — decides nothing.)
 *  2. O STOPPED INHERITING K ({@see stopInheriting()}). Not offered.
 *  3. The ENVIRONMENT has an active K. Offered — inherited.
 *
 * With no organization known (the plain sign-in page, before anybody has said who they
 * are) only the environment's active providers are offered.
 *
 * WHAT INHERITING DOES NOT DO is enrol anybody anywhere. Signing in through an environment
 * provider makes no membership (see the federation flow), even when the button was pressed
 * on one organization's page: a provider anyone in the world can hold an account with is
 * not a statement that its holder belongs to that organization. And stopping inheritance is
 * a matter of which buttons a page shows — it is not access control. An organization that
 * must keep people out of every other way in requires SSO.
 */
interface SignInProviders
{
    /**
     * The providers offered on a sign-in page after inheritance: organization `$organizationId`'s,
     * or with null the environment's alone. Active connections only, one per provider key,
     * ordered by key so the buttons do not rearrange themselves between loads.
     *
     * @return list<Connection>
     */
    public function offeredTo(?string $organizationId): array;

    /**
     * The environment's own catalogue providers, in every status, ordered by key — the
     * administration view, where a provider that is turned off is still listed.
     *
     * @return list<Connection>
     */
    public function environmentProviders(): array;

    /**
     * Stop offering the environment's `$provider` on one organization's page.
     *
     * @return bool whether anything changed
     */
    public function stopInheriting(string $organizationId, string $provider): bool;

    /**
     * Offer the environment's `$provider` on the organization's page again.
     *
     * @return bool whether anything changed
     */
    public function resumeInheriting(string $organizationId, string $provider): bool;

    /**
     * The provider keys an organization has stopped inheriting, sorted.
     *
     * @return list<string>
     */
    public function notInheritedBy(string $organizationId): array;

    /**
     * Every organization in the environment that stopped inheriting something, in one read.
     *
     * @return array<string, list<string>> organization id => provider keys, both sorted
     */
    public function optOuts(): array;

    /**
     * Create a catalogue connection as a DRAFT, optionally under an id reserved beforehand.
     *
     * The reserved id exists for the one value a provider must be given before anything is
     * saved: the redirect URI, which contains the connection's id. A console that reserves
     * the id when it draws the setup form can show the REAL URI to copy into the provider's
     * own console, instead of a placeholder the administrator has to come back and fix.
     *
     * @param  array<string, mixed>  $config  sealed at rest, exactly as {@see Connections::create()}
     * @param  string|null  $id  a ULID nobody has used yet; null mints one
     *
     * @throws InvalidAssertion for an unknown provider, or a reserved id that is not a
     *                          ULID or is already taken
     */
    public function create(
        ?string $organizationId,
        string $provider,
        ConnectionType $type,
        string $name,
        array $config,
        ?string $id = null,
    ): Connection;
}

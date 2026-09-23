<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\Contracts\BackchannelLogout;
use Cbox\Id\OAuthServer\Jobs\DeliverBackchannelLogout;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\SessionParticipant;
use Cbox\Id\OAuthServer\Support\SessionIdentifier;
use Cbox\Id\OAuthServer\ValueObjects\AccessWithdrawal;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;
use Cbox\Id\OAuthServer\ValueObjects\SessionParticipation;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Log;

/**
 * Decides WHOM to tell when a session ends, and queues the telling.
 *
 * WHICH TOKEN EACH RELYING PARTY GETS (§2.4 allows `sub`, `sid`, or both):
 *
 * - A session ended → `sub` + `sid`, one token per session. Both, because an RP keyed on
 *   either can act on it, and `sub` alone would sign the person out of their OTHER
 *   sessions at that app, which nobody asked for.
 * - The person signed out everywhere → one `sub`-only token per app: "every session of
 *   this person" is exactly what `sub` alone means, and it also reaches sessions we have
 *   no record of. Except for an RP that registered `backchannel_logout_session_required`:
 *   it gets one `sub` + `sid` token per recorded session, because a token without `sid`
 *   is one it told us it cannot use.
 * - Access withdrawn in ONE organization or from ONE app → per-session tokens where the
 *   sessions are known, so leaving one organization does not end an app session in
 *   another; `sub`-only for a grant with no recorded session, because over-signing a
 *   person out is recoverable and leaving them signed in is not.
 *
 * Participations are marked ended before anything is queued, so a logout delivered twice
 * — the outbox is at-least-once, people double-click "sign out everywhere" — notifies
 * each relying party once.
 *
 * Jobs are queued AFTER COMMIT: a sign-out inside a transaction that then rolls back must
 * not have told the apps the person left.
 */
class BackchannelLogoutService implements BackchannelLogout
{
    // Lazy per-call resolution of the ambient environment: this is a singleton and
    // EnvironmentContext is scoped — see the trait.
    use ResolvesEnvironment;

    public function participate(SessionParticipation $participation): void
    {
        if ($participation->sessionId === null || $participation->sessionId === '') {
            return;
        }

        // Found or created, race-safe: two tabs redeeming codes from the same session
        // for the same client land on one row. An ENDED row is left ended — a code minted
        // before a sign-out and redeemed after it must not bring the session back to life.
        SessionParticipant::query()->firstOrCreate(
            ['session_id' => $participation->sessionId, 'client_id' => $participation->clientId],
            ['user_id' => $participation->userId, 'organization_id' => $participation->organizationId],
        );
    }

    public function sessionEnded(string $sessionId): void
    {
        $rows = SessionParticipant::query()
            ->where('session_id', $sessionId)
            ->whereNull('ended_at')
            ->get();

        foreach ($rows->groupBy('user_id') as $userId => $held) {
            $this->notify((string) $userId, $held, [], subjectWide: false);
        }
    }

    public function subjectSignedOut(string $userId): void
    {
        $rows = SessionParticipant::query()
            ->where('user_id', $userId)
            ->whereNull('ended_at')
            ->get();

        $this->notify($userId, $rows, [], subjectWide: true);
    }

    public function accessWithdrawn(AccessWithdrawal $withdrawal): void
    {
        $rows = SessionParticipant::query()
            ->where('user_id', $withdrawal->userId)
            ->whereNull('ended_at')
            ->when($withdrawal->organizationId !== null, fn ($query) => $query->where('organization_id', $withdrawal->organizationId))
            ->when($withdrawal->clientId !== null, fn ($query) => $query->where('client_id', $withdrawal->clientId))
            ->get();

        $grants = array_values(array_filter(
            $withdrawal->grants,
            static fn (SessionParticipation $grant): bool => $grant->userId === $withdrawal->userId
                && ($withdrawal->clientId === null || $grant->clientId === $withdrawal->clientId),
        ));

        $this->notify($withdrawal->userId, $rows, $grants, $withdrawal->isSubjectWide());
    }

    /**
     * @param  Collection<int, SessionParticipant>  $rows
     * @param  list<SessionParticipation>  $grants
     */
    private function notify(string $userId, Collection $rows, array $grants, bool $subjectWide): void
    {
        $environmentId = $this->environments()->current()?->environmentKey();

        // Every row read here was read through the environment scope, so there is none
        // without an environment — but a job must carry one, and inventing it is not an option.
        if ($environmentId === null) {
            return;
        }

        // client_id => the set of session ids it was signed in from.
        $sessionsByClient = [];

        foreach ($rows as $row) {
            $sessionsByClient[$row->client_id][$row->session_id] = true;
        }

        foreach ($grants as $grant) {
            $sessionsByClient[$grant->clientId] ??= [];

            if ($grant->sessionId !== null && $grant->sessionId !== '') {
                $sessionsByClient[$grant->clientId][$grant->sessionId] = true;
            }
        }

        if ($rows->isNotEmpty()) {
            SessionParticipant::query()
                ->whereKey($rows->modelKeys())
                ->whereNull('ended_at')
                ->update(['ended_at' => now()]);
        }

        if ($sessionsByClient === []) {
            return;
        }

        $clients = Client::query()
            ->whereIn('client_id', array_map('strval', array_keys($sessionsByClient)))
            ->whereNotNull('backchannel_logout_uri')
            ->get();

        foreach ($clients as $client) {
            foreach ($this->notices($client, $userId, array_keys($sessionsByClient[$client->client_id] ?? []), $subjectWide) as $notice) {
                DeliverBackchannelLogout::dispatch($environmentId, $notice->clientId, $notice->subject, $notice->sid)
                    ->afterCommit();
            }
        }
    }

    /**
     * @param  list<string|int>  $sessionIds
     * @return list<LogoutNotice>
     */
    private function notices(Client $client, string $userId, array $sessionIds, bool $subjectWide): array
    {
        if ($client->backchannel_logout_session_required === false && ($subjectWide || $sessionIds === [])) {
            return [new LogoutNotice($client->client_id, $userId)];
        }

        if ($sessionIds === []) {
            // Session required, and no session on record — a grant from before sessions
            // were recorded, or one no session issued. A token without `sid` is one this
            // RP told us it cannot use; say so rather than send it.
            Log::notice('cbox-id: back-channel logout skipped; the client requires sid and no session is known', [
                'client_id' => $client->client_id,
            ]);

            return [];
        }

        return array_map(
            static fn (string|int $sessionId): LogoutNotice => new LogoutNotice(
                $client->client_id,
                $userId,
                SessionIdentifier::sid((string) $sessionId),
            ),
            $sessionIds,
        );
    }
}

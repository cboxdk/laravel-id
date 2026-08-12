<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\ExternalActions\Payloads\PasswordChangePayload;
use Cbox\Id\ExternalActions\Payloads\RegistrationPayload;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\PasswordExpiry;
use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\Identity\Exceptions\IdentityAlreadyLinked;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Identity\ValueObjects\FederatedProvisioning;
use Cbox\Id\Identity\ValueObjects\LinkedIdentity;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see Subjects} resolver: a self-contained user store over the
 * platform's own (optional) users table, suitable for greenfield installs. Host
 * apps that already have users bind their own resolver instead — this class is
 * never forced on them. It returns opaque {@see Subject} value objects, never
 * the underlying model, so nothing downstream depends on the storage shape.
 *
 * The registration and password-change inline hooks fire from here, for the same
 * reason the password policy is enforced from here (see {@see hashUnderPolicy()}):
 * this class is where an account and a credential are actually WRITTEN, so every
 * caller — signup, invitation, reset, admin assignment, JIT federated provisioning —
 * passes the gate without having to remember to. A host that binds its own
 * {@see Subjects} resolver owns its own store, and therefore owns running these hook
 * points itself; {@see ActionContext::for()} and the payload value objects are public
 * so it can, in one line, with the same wire shape.
 */
class DatabaseSubjects implements Subjects
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly Hasher $hasher,
        private readonly HashVerifier $verifier,
        private readonly PasswordPolicyGuard $policy,
        private readonly PasswordExpiry $ages,
        private readonly ActionPipeline $actions,
    ) {}

    /**
     * Apply the tenant's policy and retain the resulting hash.
     *
     * This sits on the PRIMITIVE rather than on each caller for a reason the review found
     * the hard way: with the guard bolted onto individual services, signup, invitation
     * acceptance and every future path silently inherited whatever floor the calling form
     * happened to hardcode. Enforcing where the credential is actually written means a
     * caller has to go out of its way to bypass the policy instead of out of its way to
     * honour it.
     *
     * The hash written to history is the one just computed, so reuse is compared against
     * exactly what authentication will check.
     */
    private function hashUnderPolicy(string $subjectId, string $password): string
    {
        $this->policy->assertAcceptable($password, $subjectId);

        $hash = $this->hasher->make($password);

        $this->policy->remember($subjectId, $hash);

        // Start the max-age clock here for the same reason the policy is applied here:
        // a timestamp kept by the callers is a timestamp some caller forgets.
        $this->ages->record($subjectId);

        return $hash;
    }

    public function find(string $id): ?Subject
    {
        $model = $this->query()->whereKey($id)->first();

        return $model === null ? null : $this->toSubject($model);
    }

    public function findMany(array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        $subjects = [];

        foreach ($this->query()->whereKey(array_values(array_unique($ids)))->get() as $model) {
            $subject = $this->toSubject($model);
            $subjects[$subject->id] = $subject;
        }

        return $subjects;
    }

    public function findByEmail(string $email): ?Subject
    {
        $model = $this->query()->where('email', $email)->first();

        return $model === null ? null : $this->toSubject($model);
    }

    public function create(string $email, ?string $name = null, ?string $password = null): Subject
    {
        // Inline hook: the host's gate on account creation, BEFORE anything is
        // written — an allowlisted-domains rule, a fraud check on the address, a
        // "this tenant's seats are full" answer only the host's billing system has.
        //
        // FAIL POLICY — fail-closed. This is a gate on a write that is awkward to
        // undo, and a signup that cannot be checked is a signup that waits; the
        // operation is user-initiated and low-volume, so the availability cost of
        // refusing is bounded to the person clicking the button.
        $this->assertAllowed(HookPoint::PreRegistration, ActionContext::for(
            RegistrationPayload::before($email, $name, $password !== null),
        ));

        $model = $this->newModel();
        $model->fill(['email' => $email, 'name' => $name, 'status' => UserStatus::Active]);
        $hash = null;

        if ($password !== null) {
            // There is no subject id yet, so no reuse history to compare against — but
            // length and the breach corpus bind at signup exactly as they do later.
            $this->policy->assertAcceptableForNewSubject($password);

            $model->setAttribute('password', $hash = $this->hasher->make($password));
        }

        $model->save();

        $subject = $this->toSubject($model);

        if ($hash !== null) {
            $this->policy->remember($subject->id, $hash);
            $this->ages->record($subject->id);
        }

        $this->events->emit(new DomainEvent('user.created', ['user_id' => $subject->id, 'email' => $email]));
        $this->audit->record(new AuditEvent(
            action: 'user.created',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $subject->id,
            context: ['email' => $email],
        ));

        // The account now exists and has an id. Synchronous, in-request notification
        // for hosts that need to act on it before the response goes out — the
        // `user.created` webhook says the same thing, but asynchronously.
        //
        // Cannot veto ({@see HookPoint::vetoable()}): the row is committed and this
        // hook has no way to unmake it. Fail-open for the same reason — there is no
        // decision here to fail closed to.
        $this->actions->run(HookPoint::PostRegistration, ActionContext::for(
            RegistrationPayload::after($subject->id, $email, $name, $hash !== null),
        ));

        return $subject;
    }

    public function provisionFederated(FederatedPrincipal $principal): Subject
    {
        return $this->resolveFederated($principal)->subject;
    }

    /**
     * The same resolution, but saying whether this call CREATED the account.
     *
     * A first-sight federated account is a signup, and a signup has obligations a
     * sign-in does not: the address is unverified until we verify it ourselves, and the
     * person holds exactly one way in — so if the provider is unreachable, or they lose
     * that account, they lose this one. Callers cannot act on either without being told
     * which case they are in, and inferring it from an unverified email or an absent
     * password eventually guesses wrong about someone who never finished setting up.
     */
    public function resolveFederated(FederatedPrincipal $principal): FederatedProvisioning
    {
        return DB::transaction(function () use ($principal): FederatedProvisioning {
            // Returning identity — the exact (provider, subject, connection) is ours.
            $link = $this->linkQuery($principal)->first();

            if ($link !== null) {
                $existing = $this->find($link->user_id);

                if ($existing !== null) {
                    return new FederatedProvisioning($existing, created: false);
                }
            }

            // NEVER merge a new identity into an existing account by email — that
            // is the account-takeover vector. Linking must be explicit (link()).
            if ($principal->email !== null && $this->findByEmail($principal->email) !== null) {
                throw AccountExistsForEmail::make($principal->email);
            }

            // First sight, no conflict: a fresh account owned by this identity.
            $email = $principal->email ?? $principal->subject.'@'.$principal->provider.'.federated';

            $subject = $this->create($email, $principal->name);

            // CARRY THE PROVIDER'S VERIFICATION ACROSS. A federated account has no local
            // verification flow to complete — nobody sends it a confirmation link — so an
            // address stored unverified stays unverified for the life of the account, and
            // our own `/oauth/userinfo` then reports `email_verified: false` about an
            // address Google or Entra had already proven. Only an explicit true crosses:
            // see FederatedPrincipal::$emailVerified on why null is not false.
            if ($principal->emailVerified === true && $principal->email !== null) {
                $this->markEmailVerified($subject->id, $email);

                $subject = $this->find($subject->id) ?? $subject;
            }

            $this->writeLink($subject->id, $principal);

            return new FederatedProvisioning($subject, created: true);
        });
    }

    public function link(string $subjectId, FederatedPrincipal $principal): void
    {
        // Guard the check-then-insert against a duplicate concurrent link of the
        // same identity, exactly like {@see provisionFederated()}. The natural
        // uniqueness index (environment_id, provider, subject, connection_id) does
        // NOT catch a social link, because its `connection_id` is null and SQL
        // treats NULLs as distinct — so two racing calls would both pass the
        // existence check and write two rows. Running inside one transaction with
        // the lookup taken FOR UPDATE serializes them: the second sees the first's
        // row (or its lock) instead of inserting a duplicate.
        DB::transaction(function () use ($subjectId, $principal): void {
            $existing = $this->linkQuery($principal)->lockForUpdate()->first();

            if ($existing !== null) {
                if ($existing->user_id !== $subjectId) {
                    throw IdentityAlreadyLinked::make($principal->provider);
                }

                return; // already linked to this subject
            }

            $this->writeLink($subjectId, $principal);
        });
    }

    public function linkedIdentities(string $subjectId): array
    {
        return array_values(
            IdentityLink::query()
                ->where('user_id', $subjectId)
                ->orderBy('created_at')
                ->get()
                ->map(fn (IdentityLink $link): LinkedIdentity => new LinkedIdentity($link->provider, $link->subject))
                ->all()
        );
    }

    public function unlink(string $subjectId, string $provider): void
    {
        IdentityLink::query()
            ->where('user_id', $subjectId)
            ->where('provider', $provider)
            ->delete();
    }

    /**
     * Resolve a federated identity within its namespace. An SSO **connection**
     * (`connection_id` set) is an org-configured — hence untrusted — IdP, so its
     * subject namespace MUST be scoped to that connection: without this, an admin
     * who controls one org's IdP could assert another user's NameID/sub and be
     * handed that user's account (cross-tenant takeover). Social providers
     * (`connection_id` null) own a globally-unique namespace, so they stay global.
     *
     * @return Builder<IdentityLink>
     */
    private function linkQuery(FederatedPrincipal $principal): Builder
    {
        $query = IdentityLink::query()
            ->where('provider', $principal->provider)
            ->where('subject', $principal->subject);

        return $principal->connectionId === null
            ? $query->whereNull('connection_id')
            : $query->where('connection_id', $principal->connectionId);
    }

    private function writeLink(string $subjectId, FederatedPrincipal $principal): void
    {
        IdentityLink::query()->create([
            'user_id' => $subjectId,
            'provider' => $principal->provider,
            'subject' => $principal->subject,
            'connection_id' => $principal->connectionId,
            'raw' => $principal->raw,
        ]);

        $this->events->emit(new DomainEvent('identity.linked', [
            'user_id' => $subjectId,
            'provider' => $principal->provider,
        ]));
        $this->audit->record(new AuditEvent(
            action: 'identity.linked',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $subjectId,
            context: ['provider' => $principal->provider, 'subject' => $principal->subject],
        ));
    }

    public function verifyPassword(string $subjectId, string $password): bool
    {
        $model = $this->query()->whereKey($subjectId)->first();

        // A deactivated/locked account never authenticates, even with the right
        // password — the status gate travels with the credential check.
        if ($model === null || $model->getAttribute('status') !== UserStatus::Active) {
            // Constant-cost dummy verify so a missing/inactive account takes the
            // same time as a real one — no username-enumeration timing oracle.
            $this->verifier->verify($password, $this->dummyHash());

            return false;
        }

        $hash = $model->getAttribute('password');

        if (! is_string($hash) || $hash === '') {
            return false;
        }

        // The registry is deny-by-default: a hash whose format no registered
        // verifier understands (including an unsupported foreign hash that slipped
        // in) fails here — never a silent pass. This covers the platform's own
        // hashes (bcrypt/argon2 via the native verifier) and any host-registered
        // legacy format the same way.
        if (! $this->verifier->verify($password, $hash)) {
            return false;
        }

        // Correct password. Lazy migration: if the stored hash is a foreign/legacy
        // format, or the platform algorithm with weaker-than-current parameters,
        // re-hash the just-verified plaintext with the platform hasher and persist
        // it — so an imported bcrypt hash self-upgrades to argon2id on first login
        // and every subsequent login uses the platform standard.
        if ($this->verifier->needsRehash($hash)) {
            $this->upgradeHash($model, $password);
        }

        return true;
    }

    /**
     * Replace a just-verified legacy/foreign hash with a fresh platform-hasher
     * hash of the same password. The model's `hashed` cast passes an
     * already-hashed value through untouched, so no double-hashing.
     */
    private function upgradeHash(Model $model, string $password): void
    {
        $model->setAttribute('password', $this->hasher->make($password));
        $model->save();

        $this->audit->record(new AuditEvent(
            action: 'user.password_rehashed',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $this->keyOf($model),
        ));
    }

    private ?string $dummyHash = null;

    /** A valid hash of an unguessable value, used to equalize miss-path timing. */
    private function dummyHash(): string
    {
        return $this->dummyHash ??= $this->hasher->make('cbox-id::no-such-account');
    }

    public function isActive(string $subjectId): bool
    {
        $model = $this->query()->whereKey($subjectId)->first();

        return $model !== null && $model->getAttribute('status') === UserStatus::Active;
    }

    public function deactivate(string $subjectId): void
    {
        $this->transitionStatus($subjectId, UserStatus::Disabled, 'user.deactivated');

        // AND EVERY GRANT THEY HOLD, which is the half that outlives them.
        //
        // Deprovisioning revoked sessions and left the OAuth grants alone, and nothing on
        // the refresh path asks whether the person still exists — `UserStatus` appears
        // nowhere in `src/OAuthServer`. So a leaver's connected application went on
        // exchanging its refresh token indefinitely: the account was disabled, they could
        // not sign in, and the CLI on their laptop kept working. That is the exact case
        // deprovisioning is bought for.
        //
        // Here rather than at each caller — SCIM, directory sync, an administrator in the
        // console — because "this person no longer has access" has to mean the same thing
        // however it is said, and a caller that forgets is a caller that leaves a door
        // open. The revoker is a no-op when they hold none.
        app(SubjectGrantRevoker::class)->revokeGrantsForUser($subjectId);
    }

    public function reactivate(string $subjectId): void
    {
        $this->transitionStatus($subjectId, UserStatus::Active, 'user.reactivated');
    }

    private function transitionStatus(string $subjectId, UserStatus $status, string $action): void
    {
        $model = $this->query()->whereKey($subjectId)->first();

        if ($model === null || $model->getAttribute('status') === $status) {
            return;
        }

        $model->setAttribute('status', $status);
        $model->save();

        $this->events->emit(new DomainEvent($action, ['user_id' => $this->keyOf($model)]));
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $this->keyOf($model),
            context: ['status' => $status->value],
        ));
    }

    public function setPassword(string $subjectId, string $password): void
    {
        $model = $this->query()->whereKey($subjectId)->first();

        if ($model === null) {
            return;
        }

        $id = $this->keyOf($model);

        // Inline hook: the host's own rule on top of the tenant's AuthPolicy — "this
        // account may not change its password outside a change window", "an SSO-backed
        // account has no local password", a SIEM that must approve the change.
        //
        // The hook is told WHO, never WHAT: no plaintext and no hash crosses the wire
        // to a customer-controlled URL (see PasswordChangePayload). A rule that needs
        // the secret runs in-process, behind Action or BreachedPasswordCheck.
        //
        // FAIL POLICY — fail-closed. It gates a credential write, and a host that put
        // a rule here meant it; an unreachable rule must not be a bypassed rule.
        //
        // Not fired by storeCredential(): that path takes an ALREADY-HASHED credential
        // during a bulk migration, where the "change" happened in the system being
        // migrated from and where firing per user would mean one blocking HTTP call
        // per imported row.
        $this->assertAllowed(HookPoint::PrePasswordChange, ActionContext::for(
            PasswordChangePayload::before($id),
        ));

        $model->setAttribute('password', $this->hashUnderPolicy($id, $password));
        $model->save();

        $this->audit->record(new AuditEvent(
            action: 'user.password_set',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $id,
        ));

        // Notification only — the credential is written and cannot be taken back, so
        // this point does not veto and fails open.
        $this->actions->run(HookPoint::PostPasswordChange, ActionContext::for(
            PasswordChangePayload::after($id),
        ));
    }

    /**
     * Run a vetoing hook point and turn a veto into the exception the caller sees.
     *
     * @throws ActionDenied
     */
    private function assertAllowed(HookPoint $hookPoint, ActionContext $context): void
    {
        $outcome = $this->actions->run($hookPoint, $context);

        if (! $outcome->allowed) {
            throw ActionDenied::because($outcome->reason);
        }
    }

    public function storeCredential(string $subjectId, string $passwordHash): void
    {
        // Write through the query builder, NOT setAttribute: the model's `hashed`
        // cast would re-hash any value it doesn't recognize as already-hashed
        // (e.g. a Firebase-scrypt string), corrupting a foreign credential. A raw
        // update stores the provider's hash verbatim so lazy migration can verify
        // and then upgrade it on first login. The environment scope still applies.
        $updated = $this->query()->whereKey($subjectId)->update(['password' => $passwordHash]);

        if ($updated === 0) {
            return;
        }

        $this->audit->record(new AuditEvent(
            action: 'user.credential_imported',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $subjectId,
        ));
    }

    public function update(string $subjectId, ?string $name = null, ?string $email = null): Subject
    {
        $model = $this->query()->whereKey($subjectId)->firstOrFail();

        $changed = [];

        if ($name !== null && $this->stringAttribute($model, 'name') !== $name) {
            $model->setAttribute('name', $name === '' ? null : $name);
            $changed[] = 'name';
        }

        if ($email !== null && mb_strtolower($this->stringAttribute($model, 'email') ?? '') !== mb_strtolower($email)) {
            $model->setAttribute('email', $email);

            // An administrator asserting an address is not its owner proving one. Clearing
            // the verification is what stops this being an account-takeover primitive:
            // set an address you control, keep the verified flag, and every recovery path
            // now points at you.
            $model->setAttribute('email_verified_at', null);
            $changed[] = 'email';
        }

        if ($changed === []) {
            return $this->toSubject($model);
        }

        $model->save();

        $this->audit->record(new AuditEvent(
            action: 'user.updated',
            actorType: ActorType::User,
            targetType: 'user',
            targetId: $subjectId,
            context: ['changed' => $changed],
        ));

        // Emitting this is what makes `user.updated` real: the webhook picker has offered
        // it all along with nothing emitting it, and the outbound SCIM path maps it to an
        // Upsert, so a profile change reached no downstream application until now.
        $this->events->emit(new DomainEvent('user.updated', [
            'user_id' => $subjectId,
            'changed' => $changed,
        ]));

        return $this->toSubject($model);
    }

    public function markEmailVerified(string $subjectId, string $email): void
    {
        $model = $this->query()->whereKey($subjectId)->first();

        // Ignore a stale confirmation: if the address changed since the token was
        // issued, the old link must not verify the new address.
        if ($model === null || $this->stringAttribute($model, 'email') !== $email) {
            return;
        }

        if ($model->getAttribute('email_verified_at') !== null) {
            return;
        }

        $model->setAttribute('email_verified_at', now());
        $model->save();

        $this->audit->record(new AuditEvent(
            action: 'user.email_verified',
            actorType: ActorType::User,
            actorId: $this->keyOf($model),
            targetType: 'user',
            targetId: $this->keyOf($model),
        ));
    }

    private function toSubject(Model $model): Subject
    {
        $status = $model->getAttribute('status');

        return new Subject(
            id: $this->keyOf($model),
            email: $this->stringAttribute($model, 'email'),
            name: $this->stringAttribute($model, 'name'),
            emailVerified: $model->getAttribute('email_verified_at') !== null,
            // The row this was loaded from already carries the status, so a caller that
            // has to re-check standing ({@see Subject::admitsSignIn()}) need not read the
            // same row a second time. Left null if the cast ever hands back something
            // else, which keeps "ask the store" as the honest fallback rather than
            // guessing a status onto an account.
            status: $status instanceof UserStatus ? $status : null,
        );
    }

    private function keyOf(Model $model): string
    {
        $key = $model->getKey();

        return is_scalar($key) ? (string) $key : '';
    }

    private function stringAttribute(Model $model, string $key): ?string
    {
        $value = $model->getAttribute($key);

        return is_string($value) ? $value : null;
    }

    /**
     * @return Builder<User>
     */
    private function query(): Builder
    {
        $model = $this->modelClass();

        return $model::query();
    }

    private function newModel(): Model
    {
        $model = $this->modelClass();

        return new $model;
    }

    /**
     * The model backing the default store. A host may override it via
     * `cbox-id.models.user`, but it MUST extend the package {@see User} — that is
     * what carries `BelongsToEnvironment` and the `(environment_id, email)` unique
     * key, so a plain Eloquent model would silently lose per-environment scoping
     * on the users table. Anything else falls back to the package default.
     *
     * @return class-string<User>
     */
    private function modelClass(): string
    {
        $configured = config('cbox-id.models.user');

        return is_string($configured) && is_a($configured, User::class, true)
            ? $configured
            : User::class;
    }
}

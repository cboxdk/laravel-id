<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\Identity\Exceptions\IdentityAlreadyLinked;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
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
 */
class DatabaseSubjects implements Subjects
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly Hasher $hasher,
        private readonly HashVerifier $verifier,
    ) {}

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
        $model = $this->newModel();
        $model->fill(['email' => $email, 'name' => $name, 'status' => UserStatus::Active]);

        if ($password !== null) {
            $model->setAttribute('password', $this->hasher->make($password));
        }

        $model->save();

        $subject = $this->toSubject($model);

        $this->events->emit(new DomainEvent('user.created', ['user_id' => $subject->id, 'email' => $email]));
        $this->audit->record(new AuditEvent(
            action: 'user.created',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $subject->id,
            context: ['email' => $email],
        ));

        return $subject;
    }

    public function provisionFederated(FederatedPrincipal $principal): Subject
    {
        return DB::transaction(function () use ($principal): Subject {
            // Returning identity — the exact (provider, subject, connection) is ours.
            $link = $this->linkQuery($principal)->first();

            if ($link !== null) {
                $existing = $this->find($link->user_id);

                if ($existing !== null) {
                    return $existing;
                }
            }

            // NEVER merge a new identity into an existing account by email — that
            // is the account-takeover vector. Linking must be explicit (link()).
            if ($principal->email !== null && $this->findByEmail($principal->email) !== null) {
                throw AccountExistsForEmail::make($principal->email);
            }

            // First sight, no conflict: a fresh account owned by this identity.
            $subject = $this->create(
                $principal->email ?? $principal->subject.'@'.$principal->provider.'.federated',
                $principal->name,
            );

            $this->writeLink($subject->id, $principal);

            return $subject;
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
        return IdentityLink::query()
            ->where('user_id', $subjectId)
            ->orderBy('created_at')
            ->get()
            ->map(fn (IdentityLink $link): array => ['provider' => $link->provider, 'subject' => $link->subject])
            ->all();
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

        $model->setAttribute('password', $this->hasher->make($password));
        $model->save();

        $this->audit->record(new AuditEvent(
            action: 'user.password_set',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $this->keyOf($model),
        ));
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
        return new Subject(
            id: $this->keyOf($model),
            email: $this->stringAttribute($model, 'email'),
            name: $this->stringAttribute($model, 'name'),
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

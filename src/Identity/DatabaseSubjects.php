<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;
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
final class DatabaseSubjects implements Subjects
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly Hasher $hasher,
    ) {}

    public function find(string $id): ?Subject
    {
        $model = $this->query()->whereKey($id)->first();

        return $model === null ? null : $this->toSubject($model);
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
            $link = IdentityLink::query()
                ->where('provider', $principal->provider)
                ->where('subject', $principal->subject)
                ->first();

            if ($link !== null) {
                $existing = $this->find($link->user_id);

                if ($existing !== null) {
                    return $existing;
                }
            }

            $email = $principal->email ?? $principal->subject.'@'.$principal->provider.'.federated';
            $subject = $this->findByEmail($email) ?? $this->create($email, $principal->name);

            IdentityLink::query()->create([
                'user_id' => $subject->id,
                'provider' => $principal->provider,
                'subject' => $principal->subject,
                'connection_id' => $principal->connectionId,
                'raw' => $principal->raw,
            ]);

            $this->events->emit(new DomainEvent('identity.linked', [
                'user_id' => $subject->id,
                'provider' => $principal->provider,
            ]));
            $this->audit->record(new AuditEvent(
                action: 'identity.linked',
                actorType: ActorType::System,
                targetType: 'user',
                targetId: $subject->id,
                context: ['provider' => $principal->provider, 'subject' => $principal->subject],
            ));

            return $subject;
        });
    }

    public function verifyPassword(string $subjectId, string $password): bool
    {
        $model = $this->query()->whereKey($subjectId)->first();
        $hash = $model?->getAttribute('password');

        return is_string($hash) && $this->hasher->check($password, $hash);
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
     * @return Builder<Model>
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
     * The model backing the default store — a configured class (need only be an
     * Eloquent model, not a subclass of the package User) or the package default.
     *
     * @return class-string<Model>
     */
    private function modelClass(): string
    {
        $configured = config('cbox-id.models.user');

        return is_string($configured) && is_a($configured, Model::class, true)
            ? $configured
            : User::class;
    }
}

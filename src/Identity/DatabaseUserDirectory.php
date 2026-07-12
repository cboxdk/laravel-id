<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\DB;

final class DatabaseUserDirectory implements UserDirectory
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly Hasher $hasher,
    ) {}

    public function find(string $id): ?User
    {
        $model = $this->userModel();

        return $model::query()->whereKey($id)->first();
    }

    public function findByEmail(string $email): ?User
    {
        $model = $this->userModel();

        return $model::query()->where('email', $email)->first();
    }

    public function create(string $email, ?string $name = null, ?string $password = null): User
    {
        $model = $this->userModel();

        $user = new $model;
        $user->fill(['email' => $email, 'name' => $name, 'status' => UserStatus::Active]);

        if ($password !== null) {
            $user->password = $this->hasher->make($password);
        }

        $user->save();

        $this->events->emit(new DomainEvent('user.created', ['user_id' => $user->id, 'email' => $email]));
        $this->audit->record(new AuditEvent(
            action: 'user.created',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $user->id,
            context: ['email' => $email],
        ));

        return $user;
    }

    public function provisionFederated(FederatedPrincipal $principal): User
    {
        return DB::transaction(function () use ($principal): User {
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
            $user = $this->findByEmail($email) ?? $this->create($email, $principal->name);

            IdentityLink::query()->create([
                'user_id' => $user->id,
                'provider' => $principal->provider,
                'subject' => $principal->subject,
                'connection_id' => $principal->connectionId,
                'raw' => $principal->raw,
            ]);

            $this->events->emit(new DomainEvent('identity.linked', [
                'user_id' => $user->id,
                'provider' => $principal->provider,
            ]));
            $this->audit->record(new AuditEvent(
                action: 'identity.linked',
                actorType: ActorType::System,
                targetType: 'user',
                targetId: $user->id,
                context: ['provider' => $principal->provider, 'subject' => $principal->subject],
            ));

            return $user;
        });
    }

    public function verifyPassword(User $user, string $password): bool
    {
        return $user->password !== null && $this->hasher->check($password, $user->password);
    }

    public function setPassword(User $user, string $password): void
    {
        $user->password = $this->hasher->make($password);
        $user->save();

        $this->audit->record(new AuditEvent(
            action: 'user.password_set',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $user->id,
        ));
    }

    /**
     * The configured user model (your subclass, or the package default).
     *
     * @return class-string<User>
     */
    private function userModel(): string
    {
        $configured = config('cbox-id.models.user');

        return is_string($configured) && is_a($configured, User::class, true)
            ? $configured
            : User::class;
    }
}

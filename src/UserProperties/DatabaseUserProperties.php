<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\UserProperties\Contracts\UserProperties;
use Cbox\Id\UserProperties\Jobs\RelayPropertyChanges;
use Cbox\Id\UserProperties\Models\PropertyDocument;
use Cbox\Id\UserProperties\Models\PropertyNamespace;
use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Cbox\Id\UserProperties\ValueObjects\PropertySnapshot;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use stdClass;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class DatabaseUserProperties implements UserProperties
{
    use ResolvesEnvironment;

    public function __construct(private readonly Subjects $subjects, private readonly EventBus $events) {}

    public function read(string $clientId, string $userId, string $namespace): PropertySnapshot
    {
        $this->authorize($clientId, $namespace, false);
        $this->subject($userId);
        $record = PropertyDocument::query()->where('user_id', $userId)->where('namespace', $namespace)->first();

        return new PropertySnapshot($userId, $namespace, $record->data ?? new stdClass, $record->version ?? 0);
    }

    public function patch(string $clientId, string $userId, string $namespace, PropertyPatch $patch): PropertySnapshot
    {
        return DB::transaction(function () use ($clientId, $userId, $namespace, $patch): PropertySnapshot {
            // Serializes first creation, updates, and grant revocation for this namespace.
            $this->authorize($clientId, $namespace, true);
            $this->subject($userId);
            $record = PropertyDocument::query()->where('user_id', $userId)->where('namespace', $namespace)->first();
            if (($record->version ?? 0) !== $patch->version) {
                throw new ConflictHttpException('The properties changed. Read the latest version and retry your patch.');
            }
            $old = $record->data ?? new stdClass;
            $data = clone $old;
            $changed = [];
            foreach (get_object_vars($patch->set) as $key => $value) {
                if (! property_exists($data, $key) || json_encode($data->{$key}, JSON_THROW_ON_ERROR) !== json_encode($value, JSON_THROW_ON_ERROR)) {
                    $data->{$key} = $value;
                    $changed[] = $key;
                }
            }
            foreach ($patch->remove as $key) {
                if (property_exists($data, $key)) {
                    unset($data->{$key});
                    $changed[] = $key;
                }
            }
            PropertyPatch::validateDocument($data);
            if ($namespace === 'preferences') {
                PreferenceSchema::validate($data);
            }
            if ($changed === []) {
                return new PropertySnapshot($userId, $namespace, $data, $patch->version);
            }
            $record ??= new PropertyDocument;
            $record->fill(['user_id' => $userId, 'namespace' => $namespace, 'data' => $data, 'version' => $patch->version + 1]);
            $record->save();
            // Invalidation only: no custom values are copied into outbox/audit/webhooks.
            $this->events->emit(new DomainEvent($namespace === 'preferences' ? 'user.preferences.updated' : 'user.metadata.updated', [
                'event_id' => (string) Str::ulid(),
                'user_id' => $userId,
                'namespace' => $namespace,
                'changed_keys' => $changed,
                'version' => $record->version,
                'client_id' => $clientId,
                'occurred_at' => now()->toIso8601String(),
            ]));
            $pending = RelayPropertyChanges::dispatch()->afterCommit();
            $connection = config('cbox-id.webhooks.queue_connection');
            $queue = config('cbox-id.webhooks.queue');
            if (is_string($connection) && $connection !== '') {
                $pending->onConnection($connection);
            }
            if (is_string($queue) && $queue !== '') {
                $pending->onQueue($queue);
            }

            return new PropertySnapshot($userId, $namespace, $data, $record->version);
        });
    }

    private function authorize(string $clientId, string $namespace, bool $write): void
    {
        $this->environments()->requireEnvironment();
        $query = PropertyNamespace::query()->where('name', $namespace);
        $record = ($write ? $query->lockForUpdate() : $query)->first();
        if ($record === null || ! in_array($clientId, $record->readers, true)
            || ($write && ! in_array($clientId, $record->writers, true))
            || ! Client::query()->where('client_id', $clientId)->whereNull('organization_id')->exists()) {
            throw new AuthorizationException('This app cannot access this namespace.');
        }
    }

    private function subject(string $userId): void
    {
        if (! $this->subjects->isActive($userId)) {
            throw new NotFoundHttpException('User not found.');
        }
    }
}

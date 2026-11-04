<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\UserProperties\Contracts\PropertyNamespaces;
use Cbox\Id\UserProperties\Models\PropertyNamespace;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class DatabasePropertyNamespaces implements PropertyNamespaces
{
    use ResolvesEnvironment;

    public function configure(string $name, array $readers, array $writers, array $webhooks = []): PropertyNamespace
    {
        $this->environments()->requireEnvironment();
        if (preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D', $name) !== 1) {
            throw ValidationException::withMessages(['name' => 'Use 1–64 lowercase letters, digits, underscores or hyphens, starting with a letter.']);
        }
        if (count($readers) > 100 || count($webhooks) > 100
            || array_diff($writers, $readers) !== []) {
            throw ValidationException::withMessages(['readers' => 'Use at most 100 reader apps and endpoints. Writers must also be readers.']);
        }
        foreach (array_unique([...$readers, ...$writers]) as $client) {
            // Namespace grants apply to environment-wide apps only; organization-bound
            // clients must not gain environment-wide user data through this capability.
            if (! Client::query()->where('client_id', $client)->whereNull('organization_id')->exists()) {
                throw ValidationException::withMessages(['readers' => 'Choose environment-wide OAuth clients in this environment.']);
            }
        }
        foreach ($webhooks as $endpoint => $client) {
            if (! in_array($client, $readers, true) || ! WebhookEndpoint::query()->whereKey($endpoint)->whereNull('organization_id')->exists()) {
                throw ValidationException::withMessages(['webhooks' => 'Map environment webhook endpoints to reader apps in this namespace.']);
            }
        }

        return DB::transaction(function () use ($name, $readers, $writers, $webhooks): PropertyNamespace {
            $record = PropertyNamespace::query()->where('name', $name)->lockForUpdate()->first() ?? new PropertyNamespace;
            $record->fill(['name' => $name, 'readers' => array_values(array_unique($readers)), 'writers' => array_values(array_unique($writers)), 'webhooks' => $webhooks]);
            $record->save();

            return $record;
        });
    }
}

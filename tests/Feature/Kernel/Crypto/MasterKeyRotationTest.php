<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\MasterKeyRing;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\LibsodiumSecretBox;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Cbox\Id\Migration\Models\LegacyLoginDeclarationRecord;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Platform\Contracts\OperatorMfa;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config()->set('cbox-id.webhooks.verify_url', false);
});

/*
 * A master-key rotation end to end, through the real services: secrets sealed under
 * key A by the modules that own them, the key rotated to B with A kept as a previous
 * key, `cbox-id:crypto:rewrap`, then A dropped — and every secret still works.
 */

/** Make `$current` the configured key (and `$previous` the old ones), and forget every cached box. */
function useMasterKeys(string $current, ?string $previous = null): void
{
    config(['cbox-id.crypto.key' => $current, 'cbox-id.crypto.previous_keys' => $previous]);

    foreach ([SecretBox::class, KeyManager::class, TokenSigner::class, Mfa::class, OperatorMfa::class, WebhookRegistry::class, SecretVault::class] as $abstract) {
        app()->forgetInstance($abstract);
    }
}

function currentTotp(string $secret): string
{
    return app(TotpAuthenticator::class)->codeAt($secret, time());
}

it('registers every column the package seals', function (): void {
    $names = array_map(static fn (SealedColumn $column): string => $column->name(), app(SealedColumns::class)->all());

    expect($names)->toEqualCanonicalizing([
        'signing_keys.private_key_encrypted',
        'mfa_factors.secret_encrypted',
        'operator_mfa_factors.secret_encrypted',
        'vault_secrets.secret_encrypted',
        'provisioning_connections.auth_secret_encrypted',
        'directories.credentials',
        'connections.config_encrypted',
        'webhook_endpoints.secret_encrypted',
        'external_action_endpoints.secret_encrypted',
        'legacy_login_declarations.secret_encrypted',
        'pipes.client_secret_encrypted',
    ]);
});

it('describes the same context each owning model seals with', function (): void {
    // The rewrap rebuilds the context from the registration, so a registration that
    // drifted from the model would fail every row — or, worse, never be noticed until
    // the old key is dropped. Each model's own secretContext() is the reference.
    $byTable = [];

    foreach (app(SealedColumns::class)->all() as $column) {
        $byTable[$column->table] = $column;
    }

    $id = (string) Str::ulid();

    foreach ([
        new VaultSecret,
        new WebhookEndpoint,
        new Connection,
        new ProvisioningConnection,
        new ExternalActionEndpoint,
        new LegacyLoginDeclarationRecord,
        new Pipe,
    ] as $model) {
        $model->forceFill(['id' => $id]);

        expect($byTable[$model->getTable()]->contextFor($id))->toBe($model->secretContext());
    }

    $signingKey = (new SigningKey)->forceFill(['kid' => $id]);

    expect($byTable['signing_keys']->contextFor($id))->toBe($signingKey->secretContext());
});

it('rotates the master key without losing a single secret', function (): void {
    $keyA = base64_encode(random_bytes(32));
    $keyB = base64_encode(random_bytes(32));
    useMasterKeys($keyA);

    // --- Sealed under A, by the modules that own them.
    $user = $this->makeUser('rotate@example.test');
    $userTotp = app(Mfa::class)->enrollTotp($user->id, 'rotate@example.test')->secret;
    expect(app(Mfa::class)->confirmTotp($user->id, currentTotp($userTotp)))->toBeTrue();

    $operatorId = (string) Str::ulid();
    $operatorTotp = app(OperatorMfa::class)->enrollTotp($operatorId, 'op@example.test')->secret;
    expect(app(OperatorMfa::class)->confirmTotp($operatorId, currentTotp($operatorTotp)))->toBeTrue();

    $webhook = app(WebhookRegistry::class)->registerForEnvironment('https://hooks.example.test/in', ['*']);
    $vaultSecret = $this->storeVaultSecret('openai', 'openai', 'downstream-token');
    $this->grantVaultAccess($vaultSecret->id, 'agent-client-1');

    app(KeyManager::class)->activeSigningKey(SigningAlg::RS256);

    // And one envelope in the untagged form 1.21 wrote, as an upgraded install has:
    // the v1 envelope minus its prefix is byte for byte the old format.
    $legacyBox = new LibsodiumSecretBox((string) base64_decode($keyA, true));
    $legacyWebhook = app(WebhookRegistry::class)->registerForEnvironment('https://hooks.example.test/legacy', ['*']);
    $untagged = substr($legacyBox->seal('legacy-webhook-secret', $legacyWebhook->endpoint->secretContext()), strlen($legacyBox->currentPrefix()));
    DB::table('webhook_endpoints')->where('id', $legacyWebhook->endpoint->id)->update(['secret_encrypted' => $untagged]);
    expect($untagged)->not->toContain('.');

    // --- Rotate: B is current, A is kept to open what is still under it.
    useMasterKeys($keyB, $keyA);

    $this->artisan('cbox-id:doctor')->expectsOutputToContain('not yet sealed under the current key');

    // A dry run counts and writes nothing.
    $before = DB::table('webhook_endpoints')->pluck('secret_encrypted', 'id')->all();
    $this->artisan('cbox-id:crypto:rewrap', ['--dry-run' => true, '--chunk' => 1])->assertExitCode(0);
    expect(DB::table('webhook_endpoints')->pluck('secret_encrypted', 'id')->all())->toBe($before);

    // Small chunks, so the keyset walk crosses several pages.
    $this->artisan('cbox-id:crypto:rewrap', ['--chunk' => 1])
        ->expectsOutputToContain('webhook_endpoints.secret_encrypted: re-sealed 2, failed 0, still not current 0')
        ->assertExitCode(0);

    $prefix = app(MasterKeyRing::class)->currentPrefix();

    foreach (app(SealedColumns::class)->all() as $column) {
        expect(DB::table($column->table)->whereNotNull($column->column)->where($column->column, 'not like', $prefix.'%')->count())
            ->toBe(0, $column->name().' still has values under the old key');
    }

    // Re-running is a no-op: resumable by construction.
    $after = DB::table('webhook_endpoints')->pluck('secret_encrypted', 'id')->all();
    $this->artisan('cbox-id:crypto:rewrap')->assertExitCode(0);
    expect(DB::table('webhook_endpoints')->pluck('secret_encrypted', 'id')->all())->toBe($after);

    // The doctor now says the old key can go.
    $this->artisan('cbox-id:doctor')->expectsOutputToContain('are no longer needed');

    // --- Drop A entirely. Everything still opens, signs and verifies under B alone.
    useMasterKeys($keyB);

    // TOTP runs on the wall clock and refuses a step it already accepted, so let the
    // factors accept this step again rather than sleeping for the next one.
    DB::table('mfa_factors')->update(['last_used_step' => null]);
    DB::table('operator_mfa_factors')->update(['last_used_step' => null]);

    $box = app(SecretBox::class);

    expect(app(Mfa::class)->verifyTotp($user->id, currentTotp($userTotp)))->toBeTrue()
        ->and(app(OperatorMfa::class)->verifyTotp($operatorId, currentTotp($operatorTotp)))->toBeTrue()
        ->and($box->open((string) WebhookEndpoint::query()->findOrFail($webhook->endpoint->id)->secret_encrypted, $webhook->endpoint->secretContext()))->toBe($webhook->secret)
        ->and($box->open((string) WebhookEndpoint::query()->findOrFail($legacyWebhook->endpoint->id)->secret_encrypted, $legacyWebhook->endpoint->secretContext()))->toBe('legacy-webhook-secret')
        ->and($this->leaseVaultSecret($vaultSecret->id, 'agent-client-1')->secret)->toBe('downstream-token');

    $jwt = app(TokenSigner::class)->sign(['sub' => 'rotation']);
    expect(app(TokenSigner::class)->verify($jwt, [SigningAlg::RS256])->subject())->toBe('rotation');

    $this->artisan('cbox-id:doctor')->expectsOutputToContain('No rotation in progress');
});

it('leaves a value no configured key opens untouched, and fails loudly', function (): void {
    $keyA = base64_encode(random_bytes(32));
    useMasterKeys($keyA);

    $webhook = app(WebhookRegistry::class)->registerForEnvironment('https://hooks.example.test/in', ['*']);

    // Sealed under a key nobody configured — lost, or tampered with.
    $stray = (new LibsodiumSecretBox(random_bytes(32)))->seal('x', $webhook->endpoint->secretContext());
    DB::table('webhook_endpoints')->where('id', $webhook->endpoint->id)->update(['secret_encrypted' => $stray]);

    useMasterKeys(base64_encode(random_bytes(32)), $keyA);

    $this->artisan('cbox-id:crypto:rewrap', ['--column' => ['webhook_endpoints.secret_encrypted']])
        ->expectsOutputToContain($webhook->endpoint->id)
        ->assertExitCode(1);

    expect(DB::table('webhook_endpoints')->where('id', $webhook->endpoint->id)->value('secret_encrypted'))->toBe($stray);
});

it('refuses an unknown column name instead of reporting nothing to do', function (): void {
    $this->artisan('cbox-id:crypto:rewrap', ['--column' => ['nope.nothing']])
        ->expectsOutputToContain('Unknown sealed column')
        ->assertExitCode(1);
});

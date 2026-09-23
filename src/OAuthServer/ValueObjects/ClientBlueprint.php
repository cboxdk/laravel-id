<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\AccessTokenLifetime;
use Cbox\Id\OAuthServer\Support\BackchannelLogoutUri;
use Cbox\Id\OAuthServer\Support\ClientSettingsRules;
use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;
use JsonException;

/**
 * An app's configuration without its identity: everything needed to create the same app
 * in another environment, and nothing that belongs to the one it came from.
 *
 * WHAT IS LEFT OUT, AND WHY. The `client_id` is minted per environment, so a staging id
 * means nothing in production. Secrets and the registration access token are credentials,
 * and a credential is never copied — the import mints its own. The owning organization is
 * an id in the source environment. A JWK Set is left out too, public as it is: a separate
 * environment should hold separate keys, so a `private_key_jwt` blueprint is imported with
 * the target's key set passed alongside it.
 *
 * Redirect URIs, the manifest URL and the back-channel logout URI ARE carried, because
 * they are the app's configuration — but they usually name the source environment's
 * deployment. Adjust them with {@see withRedirectUris()} and friends before importing.
 *
 * The customer-API-key prefix (`api_key_prefix`) is carried too: an app promoted to
 * production should accept its customers' keys there. It is unique per environment, so an
 * import into an environment where another app already declared it is REFUSED rather than
 * silently dropped — an app that quietly accepts no keys is the worse failure. Copying an
 * app within one environment therefore means {@see withApiKeyPrefix()} (another prefix, or
 * null) first. Keys themselves never travel: they belong to the environment they were
 * issued in.
 *
 * THE SHAPE IS DETERMINISTIC AND VERSIONED. Keys are emitted in one fixed order and every
 * list is de-duplicated and sorted, so exporting the same app twice produces the same
 * bytes and a blueprint committed to a repository diffs cleanly. `version` is checked on
 * the way in: a document this code does not understand is refused, never half-read.
 *
 * It also serves as the settings payload of {@see ClientRegistry::update()}: read the
 * client's blueprint, change what you mean to, hand it back.
 */
readonly class ClientBlueprint
{
    public const VERSION = 1;

    /** Identifies the document, so a blueprint is never mistaken for some other JSON. */
    public const KIND = 'cbox-id.client-blueprint';

    private const KEYS = [
        'kind', 'version', 'name', 'client_type', 'token_endpoint_auth_method', 'grant_types',
        'redirect_uris', 'post_logout_redirect_uris', 'scopes', 'first_party', 'manifest_url',
        'access_token_ttl', 'backchannel_logout_uri', 'backchannel_logout_session_required',
        'api_key_prefix',
    ];

    /** @var list<string> */
    public array $grantTypes;

    /** @var list<string> */
    public array $redirectUris;

    /** @var list<string> */
    public array $postLogoutRedirectUris;

    /** @var list<string> */
    public array $scopes;

    /** Meaningless without a URI, so it is false whenever {@see $backchannelLogoutUri} is null. */
    public bool $backchannelLogoutSessionRequired;

    /**
     * @param  list<string>  $grantTypes
     * @param  list<string>  $redirectUris
     * @param  list<string>  $postLogoutRedirectUris
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $name,
        public ClientType $type = ClientType::Confidential,
        public ?TokenEndpointAuthMethod $tokenEndpointAuthMethod = null,
        array $grantTypes = [],
        array $redirectUris = [],
        array $postLogoutRedirectUris = [],
        array $scopes = [],
        public bool $firstParty = false,
        public ?string $manifestUrl = null,
        public ?int $accessTokenTtl = null,
        public ?string $backchannelLogoutUri = null,
        bool $backchannelLogoutSessionRequired = false,
        public ?string $apiKeyPrefix = null,
    ) {
        $this->grantTypes = self::normalize($grantTypes);
        $this->redirectUris = self::normalize($redirectUris);
        $this->postLogoutRedirectUris = self::normalize($postLogoutRedirectUris);
        $this->scopes = self::normalize($scopes);
        $this->backchannelLogoutSessionRequired = $backchannelLogoutUri !== null && $backchannelLogoutSessionRequired;
    }

    public static function fromClient(Client $client): self
    {
        return new self(
            name: $client->name,
            type: $client->type,
            // A client that signs assertions but never had its method written down still
            // exports as `private_key_jwt`. Left null, the import would read "a confidential
            // client with no key set" and mint it a bearer secret.
            tokenEndpointAuthMethod: $client->token_endpoint_auth_method
                ?? ($client->jwks !== null ? TokenEndpointAuthMethod::PrivateKeyJwt : null),
            grantTypes: array_values($client->grant_types),
            redirectUris: array_values($client->redirect_uris),
            postLogoutRedirectUris: array_values($client->post_logout_redirect_uris ?? []),
            scopes: array_values($client->scopes),
            firstParty: $client->first_party,
            manifestUrl: $client->manifest_url,
            accessTokenTtl: $client->access_token_ttl,
            backchannelLogoutUri: $client->backchannel_logout_uri,
            backchannelLogoutSessionRequired: $client->backchannel_logout_session_required,
            apiKeyPrefix: $client->api_key_prefix,
        );
    }

    /**
     * Parse and validate a blueprint document. Refuses — never drops — an unknown key, a
     * version this code does not speak, and any value that would make an unusable client.
     *
     * @param  array<array-key, mixed>  $document
     *
     * @throws InvalidClientMetadata
     */
    public static function fromArray(array $document): self
    {
        $unknown = array_diff(array_map('strval', array_keys($document)), self::KEYS);

        if ($unknown !== []) {
            // Refused rather than ignored: a document carrying `client_secret` or
            // `client_id` was written by somebody who expects them to be honoured.
            throw self::invalid('unknown key(s): '.implode(', ', $unknown));
        }

        if (($document['kind'] ?? null) !== self::KIND) {
            throw self::invalid('"kind" must be "'.self::KIND.'"');
        }

        if (($document['version'] ?? null) !== self::VERSION) {
            throw self::invalid('unsupported version; this server reads version '.self::VERSION);
        }

        $name = $document['name'] ?? null;

        if (! is_string($name) || trim($name) === '') {
            throw self::invalid('"name" must be a non-empty string');
        }

        $type = is_string($document['client_type'] ?? null) ? ClientType::tryFrom($document['client_type']) : null;

        if ($type === null) {
            throw self::invalid('"client_type" must be "confidential" or "public"');
        }

        $method = $document['token_endpoint_auth_method'] ?? null;
        $authMethod = null;

        if ($method !== null) {
            $authMethod = is_string($method) ? TokenEndpointAuthMethod::tryFrom($method) : null;

            if ($authMethod === null) {
                throw self::invalid('"token_endpoint_auth_method" is not a supported method');
            }
        }

        $firstParty = $document['first_party'] ?? false;

        if (! is_bool($firstParty)) {
            throw self::invalid('"first_party" must be a boolean');
        }

        $manifestUrl = $document['manifest_url'] ?? null;

        if ($manifestUrl !== null && (! is_string($manifestUrl) || filter_var($manifestUrl, FILTER_VALIDATE_URL) === false)) {
            throw self::invalid('"manifest_url" must be an absolute URL or null');
        }

        $ttl = $document['access_token_ttl'] ?? null;

        if ($ttl !== null && ! is_int($ttl)) {
            throw self::invalid('"access_token_ttl" must be an integer number of seconds or null');
        }

        // The three 1.19 keys are optional on the way in, so a document exported before
        // they existed still reads — as "not configured", which is what it described.
        $backchannelUri = $document['backchannel_logout_uri'] ?? null;

        if ($backchannelUri !== null && ! is_string($backchannelUri)) {
            throw self::invalid('"backchannel_logout_uri" must be a string or null');
        }

        $sessionRequired = $document['backchannel_logout_session_required'] ?? false;

        if (! is_bool($sessionRequired)) {
            throw self::invalid('"backchannel_logout_session_required" must be a boolean');
        }

        $prefix = $document['api_key_prefix'] ?? null;

        if ($prefix !== null && ! is_string($prefix)) {
            throw self::invalid('"api_key_prefix" must be a string or null');
        }

        $blueprint = new self(
            name: trim($name),
            type: $type,
            tokenEndpointAuthMethod: $authMethod,
            grantTypes: self::stringList($document, 'grant_types'),
            redirectUris: self::stringList($document, 'redirect_uris'),
            postLogoutRedirectUris: self::stringList($document, 'post_logout_redirect_uris'),
            scopes: self::stringList($document, 'scopes'),
            firstParty: $firstParty,
            manifestUrl: $manifestUrl,
            accessTokenTtl: $ttl,
            backchannelLogoutUri: $backchannelUri,
            backchannelLogoutSessionRequired: $sessionRequired,
            apiKeyPrefix: $prefix,
        );

        $blueprint->assertValid();

        return $blueprint;
    }

    /**
     * @throws InvalidClientMetadata
     */
    public static function fromJson(string $json): self
    {
        try {
            $document = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw self::invalid('not valid JSON: '.$e->getMessage());
        }

        if (! is_array($document) || array_is_list($document)) {
            throw self::invalid('must be a JSON object');
        }

        return self::fromArray($document);
    }

    /**
     * Everything a client needs to be registered this way is coherent: known grants, a
     * lifetime inside the configured bounds, well-formed redirect URIs, and an
     * authentication method that fits the client type. The JWK Set is not part of a
     * blueprint, so the `private_key_jwt` pairing is checked at import, where it is given.
     *
     * @throws InvalidClientMetadata
     */
    public function assertValid(): void
    {
        ClientSettingsRules::assertGrants($this->grantTypes, $this->type);
        ClientSettingsRules::assertRedirectUris($this->redirectUris);
        ClientSettingsRules::assertRedirectUris($this->postLogoutRedirectUris, 'post_logout_redirect_uris');
        AccessTokenLifetime::assertAcceptable($this->accessTokenTtl);

        if ($this->tokenEndpointAuthMethod !== null
            && ($this->tokenEndpointAuthMethod === TokenEndpointAuthMethod::None) !== ($this->type === ClientType::Public)) {
            throw self::invalid("token_endpoint_auth_method {$this->tokenEndpointAuthMethod->value} does not match a {$this->type->value} client");
        }

        if (in_array('authorization_code', $this->grantTypes, true) && $this->redirectUris === []) {
            throw InvalidClientMetadata::redirectUri('redirect_uris is required for the authorization_code grant');
        }

        if ($this->backchannelLogoutUri !== null) {
            BackchannelLogoutUri::assertValid($this->backchannelLogoutUri);
        }

        // The format only. Whether the prefix is free is a question about the environment
        // the blueprint lands in, answered by the registry at import and update.
        if ($this->apiKeyPrefix !== null && ApiKeyPrefix::tryFrom($this->apiKeyPrefix) === null) {
            throw self::invalid("\"api_key_prefix\" [{$this->apiKeyPrefix}] must match ".ApiKeyPrefix::PATTERN.' and not use a reserved root');
        }
    }

    /**
     * The document, keys in their fixed order, lists sorted.
     *
     * @return array{kind: string, version: int, name: string, client_type: string, token_endpoint_auth_method: string|null, grant_types: list<string>, redirect_uris: list<string>, post_logout_redirect_uris: list<string>, scopes: list<string>, first_party: bool, manifest_url: string|null, access_token_ttl: int|null, backchannel_logout_uri: string|null, backchannel_logout_session_required: bool, api_key_prefix: string|null}
     */
    public function toArray(): array
    {
        return [
            'kind' => self::KIND,
            'version' => self::VERSION,
            'name' => $this->name,
            'client_type' => $this->type->value,
            'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod?->value,
            'grant_types' => $this->grantTypes,
            'redirect_uris' => $this->redirectUris,
            'post_logout_redirect_uris' => $this->postLogoutRedirectUris,
            'scopes' => $this->scopes,
            'first_party' => $this->firstParty,
            'manifest_url' => $this->manifestUrl,
            'access_token_ttl' => $this->accessTokenTtl,
            'backchannel_logout_uri' => $this->backchannelLogoutUri,
            'backchannel_logout_session_required' => $this->backchannelLogoutSessionRequired,
            'api_key_prefix' => $this->apiKeyPrefix,
        ];
    }

    /**
     * Pretty-printed with a trailing newline, so the file a person commits is the file
     * the next export produces.
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    }

    public function withName(string $name): self
    {
        return $this->copy(name: $name);
    }

    /**
     * @param  list<string>  $grantTypes
     */
    public function withGrantTypes(array $grantTypes): self
    {
        return $this->copy(grantTypes: $grantTypes);
    }

    /**
     * @param  list<string>  $redirectUris
     */
    public function withRedirectUris(array $redirectUris): self
    {
        return $this->copy(redirectUris: $redirectUris);
    }

    /**
     * @param  list<string>  $postLogoutRedirectUris
     */
    public function withPostLogoutRedirectUris(array $postLogoutRedirectUris): self
    {
        return $this->copy(postLogoutRedirectUris: $postLogoutRedirectUris);
    }

    /**
     * @param  list<string>  $scopes
     */
    public function withScopes(array $scopes): self
    {
        return $this->copy(scopes: $scopes);
    }

    public function withFirstParty(bool $firstParty): self
    {
        return $this->copy(firstParty: $firstParty);
    }

    public function withManifestUrl(?string $manifestUrl): self
    {
        return $this->rebuild(['manifestUrl' => $manifestUrl]);
    }

    /** Null returns the client to the deployment default. */
    public function withAccessTokenTtl(?int $accessTokenTtl): self
    {
        return $this->rebuild(['accessTokenTtl' => $accessTokenTtl]);
    }

    /** Null stops the notifications (and the `sid` requirement goes with the URI). */
    public function withBackchannelLogout(?string $uri, bool $sessionRequired = false): self
    {
        return $this->rebuild(['backchannelLogoutUri' => $uri, 'backchannelLogoutSessionRequired' => $sessionRequired]);
    }

    /** Null imports the app accepting no customer API keys. */
    public function withApiKeyPrefix(?string $apiKeyPrefix): self
    {
        return $this->rebuild(['apiKeyPrefix' => $apiKeyPrefix]);
    }

    /**
     * @param  list<string>|null  $grantTypes
     * @param  list<string>|null  $redirectUris
     * @param  list<string>|null  $postLogoutRedirectUris
     * @param  list<string>|null  $scopes
     */
    private function copy(
        ?string $name = null,
        ?array $grantTypes = null,
        ?array $redirectUris = null,
        ?array $postLogoutRedirectUris = null,
        ?array $scopes = null,
        ?bool $firstParty = null,
    ): self {
        return $this->rebuild(array_filter([
            'name' => $name,
            'grantTypes' => $grantTypes,
            'redirectUris' => $redirectUris,
            'postLogoutRedirectUris' => $postLogoutRedirectUris,
            'scopes' => $scopes,
            'firstParty' => $firstParty,
        ], fn (mixed $value): bool => $value !== null));
    }

    /**
     * This blueprint with the named settings replaced — nullable ones included, which is
     * why it takes the changes as a map rather than as null-means-keep arguments.
     *
     * @param  array{name?: string, grantTypes?: list<string>, redirectUris?: list<string>, postLogoutRedirectUris?: list<string>, scopes?: list<string>, firstParty?: bool, manifestUrl?: string|null, accessTokenTtl?: int|null, backchannelLogoutUri?: string|null, backchannelLogoutSessionRequired?: bool, apiKeyPrefix?: string|null}  $changes
     */
    private function rebuild(array $changes): self
    {
        return new self(
            name: array_key_exists('name', $changes) ? $changes['name'] : $this->name,
            type: $this->type,
            tokenEndpointAuthMethod: $this->tokenEndpointAuthMethod,
            grantTypes: array_key_exists('grantTypes', $changes) ? $changes['grantTypes'] : $this->grantTypes,
            redirectUris: array_key_exists('redirectUris', $changes) ? $changes['redirectUris'] : $this->redirectUris,
            postLogoutRedirectUris: array_key_exists('postLogoutRedirectUris', $changes) ? $changes['postLogoutRedirectUris'] : $this->postLogoutRedirectUris,
            scopes: array_key_exists('scopes', $changes) ? $changes['scopes'] : $this->scopes,
            firstParty: array_key_exists('firstParty', $changes) ? $changes['firstParty'] : $this->firstParty,
            manifestUrl: array_key_exists('manifestUrl', $changes) ? $changes['manifestUrl'] : $this->manifestUrl,
            accessTokenTtl: array_key_exists('accessTokenTtl', $changes) ? $changes['accessTokenTtl'] : $this->accessTokenTtl,
            backchannelLogoutUri: array_key_exists('backchannelLogoutUri', $changes) ? $changes['backchannelLogoutUri'] : $this->backchannelLogoutUri,
            backchannelLogoutSessionRequired: array_key_exists('backchannelLogoutSessionRequired', $changes) ? $changes['backchannelLogoutSessionRequired'] : $this->backchannelLogoutSessionRequired,
            apiKeyPrefix: array_key_exists('apiKeyPrefix', $changes) ? $changes['apiKeyPrefix'] : $this->apiKeyPrefix,
        );
    }

    /**
     * @param  array<array-key, mixed>  $document
     * @return list<string>
     */
    private static function stringList(array $document, string $key): array
    {
        $value = $document[$key] ?? [];

        if (! is_array($value) || ! array_is_list($value)) {
            throw self::invalid("\"{$key}\" must be a list of strings");
        }

        $strings = [];

        foreach ($value as $item) {
            if (! is_string($item) || trim($item) === '' || preg_match('/\s/', $item) === 1) {
                throw self::invalid("\"{$key}\" must contain only non-empty strings without whitespace");
            }

            $strings[] = $item;
        }

        return $strings;
    }

    /**
     * @param  list<string>  $values
     * @return list<string>
     */
    private static function normalize(array $values): array
    {
        $unique = array_values(array_unique($values));
        sort($unique, SORT_STRING);

        return $unique;
    }

    private static function invalid(string $reason): InvalidClientMetadata
    {
        return InvalidClientMetadata::metadata('Invalid client blueprint: '.$reason);
    }
}

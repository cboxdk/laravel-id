<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Cbox\Id\Pipes\Enums\TokenRequestFormat;
use Cbox\Id\Pipes\Exceptions\InvalidPipeConfiguration;
use Cbox\Id\Pipes\PipeProviderCatalog;

/**
 * One entry in the Pipes catalogue: everything about connecting a person's account at a
 * third-party service that is the same for every customer.
 *
 * The difference from a sign-in provider ({@see ProviderTemplate})
 * is what the token is FOR. A sign-in exchanges a code once, reads who the person is and
 * throws the token away. A pipe keeps the token — and its refresh token — for as long as
 * the person stays connected, so this entry also has to know how the provider refreshes,
 * how long its tokens live when it does not say, how it revokes, and which parts of the
 * token response the app needs to call the API at all (Salesforce's `instance_url`).
 *
 * A template is DATA. Adding a provider is a new entry in {@see PipeProviderCatalog},
 * not a new code path.
 */
readonly class PipeProvider
{
    /**
     * @param  list<string>  $defaultScopes  requested when the pipe does not name its own
     * @param  array<string, string>  $authorizeParameters  fixed extras on the authorization request
     * @param  list<PipeParameter>  $parameters  per-installation values substituted into the endpoints
     * @param  list<string>  $metadataPaths  dot paths into the token response that are kept (never a credential)
     * @param  list<string>  $setupSteps  how to create the OAuth app at the provider, in its own vocabulary
     */
    public function __construct(
        public string $key,
        public string $name,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public array $defaultScopes,
        /** The base URL the app calls with the leased token — documentation, not used to call. */
        public string $apiBaseUrl,
        public bool $refreshable = true,
        /**
         * How long an access token lives when the provider's response does not say.
         *
         * Null means "does not expire": a GitHub OAuth App token, or a Notion token. A
         * number is the provider's documented session length — Salesforce answers with no
         * `expires_in` at all, and its tokens die with the session the org's policy sets
         * (two hours by default), so a connection that believed them immortal would hand
         * the app a dead token with no warning.
         */
        public ?int $assumedTokenLifetimeSeconds = null,
        public string $scopeParameter = 'scope',
        public string $scopeSeparator = ' ',
        public TokenEndpointAuthMethod $tokenEndpointAuthMethod = TokenEndpointAuthMethod::ClientSecretPost,
        public TokenRequestFormat $tokenRequestFormat = TokenRequestFormat::Form,
        /**
         * Where the token set sits in the token response, when it is not at the top.
         * Slack's user token lives under `authed_user`; the top level is the bot's.
         */
        public ?string $tokenResponsePath = null,
        public array $authorizeParameters = [],
        public array $parameters = [],
        public ?PipeRevocation $revocation = null,
        /** A GET with the access token that names the connected account, and where the name is. */
        public ?string $accountEndpoint = null,
        public ?string $accountLabelPath = null,
        /** When the token response itself names the account (Slack's workspace, Notion's). */
        public ?string $accountLabelTokenPath = null,
        public array $metadataPaths = [],
        public ?string $documentationUrl = null,
        public array $setupSteps = [],
        /**
         * The sign-in catalogue entry for the same vendor, when there is one — so a console
         * can say "you already have a Google OAuth client for sign-in; this needs its own
         * consent for the extra scopes" instead of treating them as unrelated.
         */
        public ?string $signInKey = null,
    ) {}

    /**
     * The parameter values to use: the defaults, overridden by what the pipe stores, each
     * one checked against its pattern.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, string>
     *
     * @throws InvalidPipeConfiguration when a value does not match its pattern, or names a parameter this provider does not have
     */
    public function parameterValues(array $values): array
    {
        $resolved = [];
        $known = [];

        foreach ($this->parameters as $parameter) {
            $known[] = $parameter->key;
            $value = $values[$parameter->key] ?? null;
            $value = is_string($value) && trim($value) !== '' ? trim($value) : $parameter->default;

            if (! $parameter->accepts($value)) {
                throw InvalidPipeConfiguration::parameter($this->key, $parameter->key);
            }

            $resolved[$parameter->key] = $value;
        }

        foreach (array_keys($values) as $key) {
            if (! in_array($key, $known, true)) {
                throw InvalidPipeConfiguration::parameter($this->key, (string) $key);
            }
        }

        return $resolved;
    }

    /**
     * An endpoint with this installation's parameters substituted.
     *
     * @param  array<string, mixed>  $values  the pipe's stored parameters
     * @param  array<string, string>  $extra  other placeholders (`client_id`, `refresh_token`), url-encoded here
     */
    public function endpoint(string $template, array $values, array $extra = []): string
    {
        $url = $template;

        foreach ($this->parameterValues($values) as $key => $value) {
            $url = str_replace('{'.$key.'}', rawurlencode($value), $url);
        }

        foreach ($extra as $key => $value) {
            $url = str_replace('{'.$key.'}', rawurlencode($value), $url);
        }

        return $url;
    }

    /**
     * @param  list<string>  $scopes
     */
    public function scopeString(array $scopes): string
    {
        return implode($this->scopeSeparator, $scopes);
    }
}

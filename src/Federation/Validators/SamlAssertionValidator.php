<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Validators;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use OneLogin\Saml2\Response as SamlResponse;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils as SamlUtils;
use Throwable;

/**
 * Validates a SAML 2.0 Response by wrapping onelogin/php-saml — a maintained,
 * hardened toolkit. It is trusted for the parts that are genuinely dangerous to
 * hand-roll: XML-signature verification, signature-wrapping (XSW) defense, and
 * XML parsing with external entities disabled (XXE).
 *
 * This class enforces the RP-side policy on top of it: strict mode, and
 * `wantAssertionsSigned` so an unsigned assertion is rejected.
 *
 * The connection config (sealed at rest) must contain:
 *  - `idp_entity_id`, `idp_sso_url`, `idp_x509cert` — the trusted IdP
 *  - `sp_entity_id`, `sp_acs_url` — this Relying Party's identifiers
 *
 * `$rawResponse` is the base64-encoded `SAMLResponse` as received at the ACS.
 */
final class SamlAssertionValidator implements AssertionValidator
{
    /** Common attribute names an IdP uses for email / display name. */
    private const EMAIL_CLAIMS = [
        'email',
        'mail',
        'emailAddress',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'urn:oid:0.9.2342.19200300.100.1.3',
    ];

    private const NAME_CLAIMS = [
        'name',
        'displayName',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'urn:oid:2.16.840.1.113730.3.1.241',
    ];

    public function __construct(private readonly Connections $connections) {}

    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal
    {
        $config = $this->connections->config($connection);

        try {
            $settings = new Settings($this->settings($config), true);

            // onelogin derives the "current URL" it validates Destination/Recipient
            // against from $_SERVER, which is wrong behind proxies and absent on CLI.
            // Pin it to the connection's configured ACS URL instead — the single
            // source of truth for where this SP receives assertions. Both the
            // Response construction and isValid() read $_SERVER, so both run pinned.
            [$response, $valid] = $this->withAcsUrl($this->require($config, 'sp_acs_url'), static function () use ($settings, $rawResponse): array {
                $response = new SamlResponse($settings, $rawResponse);

                return [$response, $response->isValid()];
            });
        } catch (Throwable $exception) {
            throw InvalidAssertion::make('SAML response could not be processed: '.$exception->getMessage());
        }

        if (! $valid) {
            $reason = $response->getErrorException();

            throw InvalidAssertion::make($reason instanceof Throwable ? $reason->getMessage() : 'SAML response is not valid');
        }

        $nameId = $response->getNameId();

        if (! is_string($nameId) || $nameId === '') {
            throw InvalidAssertion::make('SAML response has no NameID');
        }

        $attributes = $this->stringKeyed($response->getAttributes());

        return new FederatedPrincipal(
            provider: $connection->type->value,
            subject: $nameId,
            email: $this->firstClaim($attributes, self::EMAIL_CLAIMS),
            name: $this->firstClaim($attributes, self::NAME_CLAIMS),
            connectionId: $connection->id,
            raw: $attributes,
        );
    }

    /**
     * Pin onelogin's self-URL resolution to $acsUrl for the duration of
     * $callback by setting the $_SERVER values it reads, then restore them. This
     * decouples Destination/Recipient validation from the serving host (correct
     * behind proxies) and makes it deterministic off a web request.
     *
     * @param  callable(): array{0: SamlResponse, 1: bool}  $callback
     * @return array{0: SamlResponse, 1: bool}
     */
    private function withAcsUrl(string $acsUrl, callable $callback): array
    {
        $parts = parse_url($acsUrl);
        $parts = is_array($parts) ? $parts : [];

        $host = is_string($parts['host'] ?? null) ? $parts['host'] : 'localhost';
        $scheme = ($parts['scheme'] ?? null) === 'http' ? 'http' : 'https';
        $path = is_string($parts['path'] ?? null) ? $parts['path'] : '/';

        if (isset($parts['port'])) {
            $host .= ':'.$parts['port'];
        }

        $keys = ['HTTP_HOST', 'HTTPS', 'SCRIPT_NAME', 'PATH_INFO', 'REQUEST_URI', 'SERVER_PORT'];
        $saved = [];
        foreach ($keys as $key) {
            $saved[$key] = $_SERVER[$key] ?? null;
        }

        SamlUtils::setBaseURL(''); // clears any static host/path overrides
        $_SERVER['HTTP_HOST'] = $host;
        $_SERVER['HTTPS'] = $scheme === 'https' ? 'on' : 'off';
        $_SERVER['SCRIPT_NAME'] = $path;
        $_SERVER['REQUEST_URI'] = $path;
        unset($_SERVER['PATH_INFO'], $_SERVER['SERVER_PORT']);

        try {
            return $callback();
        } finally {
            foreach ($saved as $key => $value) {
                if ($value === null) {
                    unset($_SERVER[$key]);
                } else {
                    $_SERVER[$key] = $value;
                }
            }
        }
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    private function settings(array $config): array
    {
        return [
            'strict' => true,
            'sp' => [
                'entityId' => $this->require($config, 'sp_entity_id'),
                'assertionConsumerService' => ['url' => $this->require($config, 'sp_acs_url')],
            ],
            'idp' => [
                'entityId' => $this->require($config, 'idp_entity_id'),
                'singleSignOnService' => ['url' => $this->require($config, 'idp_sso_url')],
                'x509cert' => $this->require($config, 'idp_x509cert'),
            ],
            'security' => [
                'wantAssertionsSigned' => true,
                'requestedAuthnContext' => false,
            ],
        ];
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function require(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidAssertion::make("connection config missing [{$key}]");
        }

        return $value;
    }

    /**
     * onelogin returns an untyped array; re-key it to a typed map.
     *
     * @param  array<mixed>  $attributes
     * @return array<string, mixed>
     */
    private function stringKeyed(array $attributes): array
    {
        $typed = [];

        foreach ($attributes as $key => $value) {
            $typed[(string) $key] = $value;
        }

        return $typed;
    }

    /**
     * @param  array<string, mixed>  $attributes
     * @param  list<string>  $names
     */
    private function firstClaim(array $attributes, array $names): ?string
    {
        foreach ($names as $name) {
            $value = $attributes[$name] ?? null;

            if (is_array($value) && isset($value[0]) && is_string($value[0]) && $value[0] !== '') {
                return $value[0];
            }

            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }
}

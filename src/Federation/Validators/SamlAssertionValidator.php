<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Validators;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\ConsumedAssertion;
use Cbox\Id\Federation\Models\SamlAuthRequest;
use Cbox\Id\Federation\Saml\SamlSettings;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use DOMDocument;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
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
class SamlAssertionValidator implements AssertionValidator
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

    /**
     * Reject an assertion id we have already accepted (replay), and remember this
     * one until it expires. The unique index on `assertion_id` is the real guard.
     */
    private function guardReplay(?string $assertionId, ?int $notOnOrAfter): void
    {
        if (! is_string($assertionId) || $assertionId === '') {
            throw InvalidAssertion::make('assertion is missing an id');
        }

        $expiresAt = is_int($notOnOrAfter)
            ? Carbon::createFromTimestamp($notOnOrAfter)
            : now()->addMinutes(10);

        try {
            ConsumedAssertion::query()->create([
                'assertion_id' => $assertionId,
                'expires_at' => $expiresAt,
            ]);
        } catch (UniqueConstraintViolationException) {
            throw InvalidAssertion::make('assertion replay detected');
        }
    }

    /**
     * Resolve the outstanding AuthnRequest a response answers, or null when the
     * response carries no InResponseTo (IdP-initiated). Throws when an InResponseTo
     * is present but matches no request we issued for this connection (unsolicited
     * injection, replay, or expiry).
     */
    private function matchOutstandingRequest(Connection $connection, string $rawResponse): ?SamlAuthRequest
    {
        $inResponseTo = $this->extractInResponseTo($rawResponse);

        if ($inResponseTo === null) {
            // UNSOLICITED (IdP-initiated). Opt-in per connection, and off by default.
            //
            // Accepting it unconditionally made the ACS a login-CSRF sink: an attacker
            // with a legitimate account at the customer's IdP obtains their OWN valid
            // assertion, auto-POSTs it from a page the victim visits, and — because the
            // ACS is necessarily CSRF-exempt — the victim's browser is issued a session
            // as the ATTACKER. Everything the victim then creates lands in the attacker's
            // account. Assertion replay protection does not help: the attacker never
            // redeems the assertion themselves.
            //
            // A solicited response is bound to a request WE issued, so this is the
            // difference between "someone asked for this login" and "anyone can post one".
            $config = $this->connections->config($connection);

            if (($config['allow_idp_initiated'] ?? false) !== true) {
                throw InvalidAssertion::make(
                    'unsolicited SAML response refused: this connection does not allow IdP-initiated sign-in'
                );
            }

            return null;
        }

        $request = SamlAuthRequest::query()
            ->where('request_id', $inResponseTo)
            ->where('connection_id', $connection->id)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', now())
            ->first();

        if ($request === null) {
            throw InvalidAssertion::make('SAML response InResponseTo does not match an outstanding request');
        }

        return $request;
    }

    /**
     * Read the root element's InResponseTo attribute via onelogin's XXE-safe XML
     * loader. This is a pre-signature peek used only to locate our stored request;
     * the value is re-checked against onelogin's canonical parse inside isValid().
     */
    private function extractInResponseTo(string $rawResponse): ?string
    {
        $decoded = base64_decode($rawResponse, true);

        if (! is_string($decoded) || $decoded === '') {
            return null;
        }

        try {
            $dom = SamlUtils::loadXML(new DOMDocument, $decoded);
        } catch (Throwable) {
            return null;
        }

        if (! $dom instanceof DOMDocument || $dom->documentElement === null) {
            return null;
        }

        $value = $dom->documentElement->getAttribute('InResponseTo');

        return $value !== '' ? $value : null;
    }

    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal
    {
        $config = $this->connections->config($connection);

        // InResponseTo enforcement: a response carrying an InResponseTo must
        // reference an AuthnRequest THIS SP issued for THIS connection, defeating
        // unsolicited-response injection. No InResponseTo = IdP-initiated SSO,
        // which we allow. We match (but don't yet consume) here, then pass the id
        // to onelogin's isValid() as defense-in-depth: onelogin's own canonical
        // parse must agree, closing any signature-wrapping InResponseTo mismatch.
        $authRequest = $this->matchOutstandingRequest($connection, $rawResponse);
        $expectedRequestId = $authRequest?->request_id;

        try {
            $settings = new Settings(SamlSettings::toArray($config), true);

            // onelogin derives the "current URL" it validates Destination/Recipient
            // against from $_SERVER, which is wrong behind proxies and absent on CLI.
            // Pin it to the connection's configured ACS URL instead — the single
            // source of truth for where this SP receives assertions. Both the
            // Response construction and isValid() read $_SERVER, so both run pinned.
            [$response, $valid] = $this->withAcsUrl($this->require($config, 'sp_acs_url'), static function () use ($settings, $rawResponse, $expectedRequestId): array {
                $response = new SamlResponse($settings, $rawResponse);

                return [$response, $response->isValid($expectedRequestId)];
            });
        } catch (Throwable $exception) {
            throw InvalidAssertion::make('SAML response could not be processed: '.$exception->getMessage());
        }

        if (! $valid) {
            $reason = $response->getErrorException();

            throw InvalidAssertion::make($reason instanceof Throwable ? $reason->getMessage() : 'SAML response is not valid');
        }

        // Single-use: a captured, still-valid assertion cannot be replayed.
        $this->guardReplay($response->getAssertionId(), $response->getAssertionNotOnOrAfter());

        // The matched request is now spent — a later response can't reuse this id.
        $authRequest?->forceFill(['consumed_at' => now()])->save();

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

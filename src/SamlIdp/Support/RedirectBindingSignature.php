<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * Verifies the detached signature on an HTTP-Redirect-binding SAML message
 * (SAML bindings §3.4.4.1): the SP signs the URL-encoded
 * `SAMLRequest=…&RelayState=…&SigAlg=…` octet string, and we verify it against the
 * SP's registered certificate.
 *
 * The RSA verification is delegated to xmlseclibs (openssl underneath) with the
 * algorithm PINNED to RSA-SHA256 — the mirror image of the outbound
 * {@see RedirectBindingResponseSigner}, which builds the same octet string and
 * signs it with the same primitive. SHA-1 (the historical SAML default) and every
 * other `SigAlg` is refused before any verification is attempted, and a missing
 * `SigAlg` is never defaulted.
 *
 * The signature covers the octet string AS TRANSMITTED, not a re-encoding of the
 * decoded values, and that distinction is not academic: PHP's `urlencode()` writes
 * a space as `+` and `~` as `%7E`, while Entra and Ping percent-encode per
 * RFC 3986 (`%20`, literal `~`). Rebuilding the signed string from decoded
 * parameters therefore fails for any `RelayState` carrying a space or a `~` — an
 * intermittent, customer-specific, deep-link-only 400. So when the raw query
 * string is available we verify against those exact octets, and fall back to the
 * re-encoded reconstruction only when it is not (a host driving the API directly,
 * or a query we cannot prove these parameters came from).
 */
class RedirectBindingSignature
{
    /** The parameters that make up a redirect-binding message. */
    private const MESSAGE_PARAMETERS = ['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature'];

    /**
     * @param  string|null  $rawQueryString  the query string exactly as received,
     *                                       still percent-encoded. Defaults to the current request's; pass it
     *                                       explicitly when verifying outside an HTTP request.
     *
     * @throws InvalidAuthnRequest unknown algorithm, missing certificate, or a
     *                             signature that does not verify
     */
    public function verify(
        string $samlRequest,
        ?string $relayState,
        ?string $signature,
        ?string $sigAlg,
        ?string $certificatePem,
        ?string $rawQueryString = null,
    ): void {
        if ($signature === null || $signature === '') {
            throw InvalidAuthnRequest::make('a signed AuthnRequest is required but no Signature was supplied');
        }

        // Algorithm pin: only RSA-SHA256 is accepted — never inferred, never
        // defaulted (a missing SigAlg would otherwise mean SHA-1).
        if ($sigAlg !== XMLSecurityKey::RSA_SHA256) {
            throw InvalidAuthnRequest::make('unsupported or missing SigAlg (RSA-SHA256 required)');
        }

        if ($certificatePem === null || $certificatePem === '') {
            throw InvalidAuthnRequest::make('SP has no certificate on file to verify a signed request');
        }

        $parameters = [
            'SAMLRequest' => $samlRequest,
            'SigAlg' => $sigAlg,
            'Signature' => $signature,
        ];

        if ($relayState !== null && $relayState !== '') {
            $parameters['RelayState'] = $relayState;
        }

        $rawSignature = base64_decode($signature, true);

        if (! is_string($rawSignature) || $rawSignature === '') {
            throw InvalidAuthnRequest::make('request signature is not valid base64');
        }

        $signedQuery = $this->transmittedQuery($rawQueryString ?? $this->receivedQueryString(), $parameters)
            ?? $this->reEncodedQuery($parameters);

        try {
            $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
            $key->loadKey(SamlUtils::formatCert($certificatePem), false, true);

            $valid = $key->verifySignature($signedQuery, $rawSignature) === 1;
        } catch (Throwable $exception) {
            throw InvalidAuthnRequest::make('request signature could not be verified ('.$exception->getMessage().')');
        }

        if (! $valid) {
            throw InvalidAuthnRequest::make('request signature is invalid');
        }
    }

    /**
     * The signed octet string rebuilt from the RAW fragments of `$rawQuery`, or
     * null when that query cannot be proven to be the one these parameters came
     * from.
     *
     * Every fragment is checked to decode back to the value we were handed, and
     * every message parameter must appear exactly once — so a mismatched,
     * duplicated or absent query can never be used to verify a signature, and the
     * caller falls back to the re-encoded reconstruction. The fragments are
     * re-emitted in the fixed order the spec signs them (message, RelayState?,
     * SigAlg), never the received order.
     *
     * @param  array<string, string>  $parameters
     */
    private function transmittedQuery(?string $rawQuery, array $parameters): ?string
    {
        if ($rawQuery === null || $rawQuery === '') {
            return null;
        }

        $fragments = $this->rawFragments($rawQuery);

        if ($fragments === null) {
            return null;
        }

        foreach (self::MESSAGE_PARAMETERS as $name) {
            $expected = $parameters[$name] ?? null;
            $fragment = $fragments[$name] ?? null;

            if ($expected === null) {
                // A parameter we are not verifying over must be absent from the
                // query too — an unexpected RelayState changes the signed string.
                if ($fragment !== null) {
                    return null;
                }

                continue;
            }

            if ($fragment === null || urldecode($fragment) !== $expected) {
                return null;
            }
        }

        $query = 'SAMLRequest='.$fragments['SAMLRequest'];

        if (isset($fragments['RelayState'])) {
            $query .= '&RelayState='.$fragments['RelayState'];
        }

        return $query.'&SigAlg='.$fragments['SigAlg'];
    }

    /**
     * The signed octet string rebuilt by re-encoding the decoded parameters — the
     * best we can do without the transmitted octets, and byte-identical to what
     * onelogin's own `validateBinarySign()` reconstructs.
     *
     * @param  array<string, string>  $parameters
     */
    private function reEncodedQuery(array $parameters): string
    {
        $query = 'SAMLRequest='.urlencode($parameters['SAMLRequest']);

        if (isset($parameters['RelayState'])) {
            $query .= '&RelayState='.urlencode($parameters['RelayState']);
        }

        return $query.'&SigAlg='.urlencode($parameters['SigAlg']);
    }

    /**
     * The raw (still percent-encoded) fragment of each message parameter in the
     * query string, or null when one of them appears more than once — a duplicate
     * is an injection attempt, and which copy is "the" value differs by parser.
     *
     * @return array<string, string>|null
     */
    private function rawFragments(string $rawQuery): ?array
    {
        $fragments = [];

        foreach (explode('&', $rawQuery) as $pair) {
            $separator = strpos($pair, '=');

            if ($separator === false) {
                continue;
            }

            $name = substr($pair, 0, $separator);

            if (! in_array($name, self::MESSAGE_PARAMETERS, true)) {
                continue;
            }

            if (isset($fragments[$name])) {
                return null;
            }

            $fragments[$name] = substr($pair, $separator + 1);
        }

        return $fragments;
    }

    /**
     * The current request's query string, exactly as received. Read from the
     * request's own server bag (correct under Octane/Swoole, where the `$_SERVER`
     * superglobal is not per-request) and never trusted on its own — the caller
     * proves it matches the parameters before any signature is verified against it.
     */
    private function receivedQueryString(): ?string
    {
        try {
            $query = request()->server->get('QUERY_STRING');
        } catch (Throwable) {
            return null;
        }

        return is_string($query) && $query !== '' ? $query : null;
    }
}

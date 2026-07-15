<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Contracts;

use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\UnknownServiceProvider;
use Cbox\Id\SamlIdp\ValueObjects\AuthnRequest;
use Cbox\Id\SamlIdp\ValueObjects\SamlResponse;

/**
 * The SAML 2.0 Identity Provider protocol surface. The host app drives the flow:
 * parse the inbound AuthnRequest, authenticate the subject itself (as with the
 * OAuth authorize endpoint, the "is a user logged in" step is the host's job),
 * then ask the IdP to mint a signed Response and POST it to the SP's ACS.
 *
 * Every method is deny-by-default: an unregistered/inactive SP, a request whose
 * ACS does not match the registration, or a required-but-missing/invalid
 * signature is refused with an exception — no assertion is produced.
 */
interface SamlIdentityProvider
{
    /**
     * The IdP's SAML 2.0 metadata XML: EntityID, the SingleSignOnService endpoints
     * (HTTP-Redirect and HTTP-POST bindings), the SingleLogoutService endpoint, and
     * the signing X.509 certificate. Public, no secrets.
     */
    public function metadata(): string;

    /**
     * Decode and validate an inbound `AuthnRequest`.
     *
     * `$samlRequest` is the raw `SAMLRequest` form/query value. For the HTTP-Redirect
     * binding it is base64 + DEFLATE and the detached signature is supplied via
     * `$signature`/`$sigAlg` (the query-string signature); for the HTTP-POST binding
     * it is base64 only and the signature (if any) is the embedded XML-DSig.
     *
     * @throws InvalidAuthnRequest malformed XML/XXE, missing issuer or id, ACS
     *                             mismatch, unknown/absent required signature, or a
     *                             signature that fails to verify
     * @throws UnknownServiceProvider the issuer is not a registered, active SP
     */
    public function parseAuthnRequest(
        string $samlRequest,
        ?string $relayState = null,
        ?string $signature = null,
        ?string $sigAlg = null,
        bool $fromRedirectBinding = true,
    ): AuthnRequest;

    /**
     * Mint a signed SAML Response containing a signed Assertion for `$subjectId`,
     * addressed to the request's registered ACS and audience-restricted to the SP.
     *
     * `$attributes` is the subject/user field map (field name => value|values); it
     * is projected through the SP's `attribute_mappings` into the AttributeStatement,
     * and the NameID is read from the SP's configured `name_id_attribute`.
     *
     * @param  array<string, string|list<string>>  $attributes
     *
     * @throws UnknownServiceProvider the SP referenced by the request is no longer active
     */
    public function issueResponse(AuthnRequest $request, string $subjectId, array $attributes = []): SamlResponse;
}

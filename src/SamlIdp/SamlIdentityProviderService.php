<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Enums\AuthnContext;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Enums\SamlBinding;
use Cbox\Id\SamlIdp\Enums\SamlStatusCode;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\UnknownServiceProvider;
use Cbox\Id\SamlIdp\Models\SamlIdpNameId;
use Cbox\Id\SamlIdp\Models\SamlIdpSession;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\Support\AssertionBuilder;
use Cbox\Id\SamlIdp\Support\AuthnRequestParser;
use Cbox\Id\SamlIdp\Support\EmbeddedSignature;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\Support\MessageGuard;
use Cbox\Id\SamlIdp\Support\ReceivedEndpoint;
use Cbox\Id\SamlIdp\Support\RedirectBindingSignature;
use Cbox\Id\SamlIdp\ValueObjects\AuthnRequest;
use Cbox\Id\SamlIdp\ValueObjects\ParsedAuthnRequest;
use Cbox\Id\SamlIdp\ValueObjects\SamlError;
use Cbox\Id\SamlIdp\ValueObjects\SamlResponse as SamlResponseVo;
use DOMDocument;

/**
 * The SAML 2.0 Identity Provider. Enforces the IdP-side trust policy on top of the
 * vetted signing/verification primitives (xmlseclibs, onelogin): an assertion is
 * only ever minted for a registered, active SP, delivered only to that SP's
 * exact registered ACS, and (when required) only in answer to a signed, fresh,
 * correctly-addressed request that has not been seen before.
 */
class SamlIdentityProviderService implements SamlIdentityProvider
{
    /**
     * How far an inbound `AuthnRequest`'s IssueInstant may be from now, in both
     * directions. Wider than the SLO window on purpose: the SSO endpoint hands an
     * unauthenticated browser off to the host's login and the SAME request comes
     * back once the user has signed in, so the window has to cover a real login
     * (password + MFA), not just network latency.
     */
    /**
     * How long an issued-session record is kept.
     *
     * Long enough to outlive any realistic SP session — SLO arriving after this has
     * nothing to resolve and is refused, which is the safe direction: a logout that does
     * not happen is a nuisance, one that happens to the wrong person is an outage.
     */
    private const SESSION_RECORD_TTL_SECONDS = 60 * 60 * 24 * 30;

    private const REQUEST_FRESHNESS_SECONDS = 900;

    public function __construct(
        private readonly ServiceProviders $serviceProviders,
        private readonly IdpKeyMaterial $keyMaterial,
        private readonly AuthnRequestParser $parser,
        private readonly RedirectBindingSignature $redirectSignature,
        private readonly AssertionBuilder $assertions,
        private readonly EmbeddedSignature $embeddedSignature,
        private readonly MessageGuard $guard,
    ) {}

    /**
     * The published IdP metadata. Everything in it is derived from what this IdP
     * ACTUALLY does — an SP treats metadata as authoritative, so an attribute that
     * over-promises is not cosmetic: it is an outage on the SP's side. Hence
     * `WantAuthnRequestsSigned` follows the registered SPs' real policy, the
     * NameIDFormats are the ones this environment actually emits, and both SLO
     * bindings are advertised only because both are now verified.
     */
    public function metadata(): string
    {
        $entityId = IdpDescriptor::entityId();
        $ssoUrl = IdpDescriptor::ssoUrl();
        $sloUrl = IdpDescriptor::sloUrl();

        // Read the registrations ONCE — both derived attributes below describe the
        // same set of SPs.
        $registered = $this->activeServiceProviders();

        $md = 'urn:oasis:names:tc:SAML:2.0:metadata';
        $ds = 'http://www.w3.org/2000/09/xmldsig#';

        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = true;

        $entity = $document->createElementNS($md, 'md:EntityDescriptor');
        $entity->setAttribute('entityID', $entityId);
        $document->appendChild($entity);

        $idp = $document->createElementNS($md, 'md:IDPSSODescriptor');
        $idp->setAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $idp->setAttribute('WantAuthnRequestsSigned', $this->wantAuthnRequestsSigned($registered) ? 'true' : 'false');
        $entity->appendChild($idp);

        // Signing key descriptors — the X.509 certs SPs pin to verify our
        // assertions. One per currently-trusted key (active first, then the ones
        // rotating out) so a rotation has an overlap window instead of a cliff.
        foreach ($this->keyMaterial->published() as $certificate) {
            $keyDescriptor = $document->createElementNS($md, 'md:KeyDescriptor');
            $keyDescriptor->setAttribute('use', 'signing');
            $keyInfo = $document->createElementNS($ds, 'ds:KeyInfo');
            $x509Data = $document->createElementNS($ds, 'ds:X509Data');
            $x509Certificate = $document->createElementNS($ds, 'ds:X509Certificate');
            $x509Certificate->appendChild($document->createTextNode($this->certificateBody($certificate)));
            $x509Data->appendChild($x509Certificate);
            $keyInfo->appendChild($x509Data);
            $keyDescriptor->appendChild($keyInfo);
            $idp->appendChild($keyDescriptor);
        }

        // Single Logout endpoints. Both bindings are verified: HTTP-Redirect by the
        // detached query signature, HTTP-POST by the enveloped XML-DSig.
        foreach (SamlBinding::cases() as $binding) {
            $slo = $document->createElementNS($md, 'md:SingleLogoutService');
            $slo->setAttribute('Binding', $binding->value);
            $slo->setAttribute('Location', $sloUrl);
            $idp->appendChild($slo);
        }

        // The NameID formats EVERY registered SP can be answered under. One
        // IDPSSODescriptor serves all of them, so a format only some SPs accept is
        // a menu item that refuses whoever orders it.
        foreach ($this->advertisedNameIdFormats($registered) as $format) {
            $nameIdFormat = $document->createElementNS($md, 'md:NameIDFormat');
            $nameIdFormat->appendChild($document->createTextNode($format->value));
            $idp->appendChild($nameIdFormat);
        }

        // Single Sign-On endpoints (both bindings).
        foreach (SamlBinding::cases() as $binding) {
            $sso = $document->createElementNS($md, 'md:SingleSignOnService');
            $sso->setAttribute('Binding', $binding->value);
            $sso->setAttribute('Location', $ssoUrl);
            $idp->appendChild($sso);
        }

        return (string) $document->saveXML();
    }

    /**
     * Whether metadata should declare that AuthnRequests must be signed.
     *
     * `WantAuthnRequestsSigned` is ONE boolean on the one IDPSSODescriptor (SAML
     * metadata §2.4.3) while enforcement is per-SP (`want_authn_requests_signed`),
     * so the two can only be reconciled in one of two directions. We publish `true`
     * only when EVERY active SP requires signing, rather than enforcing signing on
     * everyone as soon as one SP requires it: the attribute is a claim about what
     * this IdP refuses, and "true" while unsigned requests are still accepted for
     * other SPs is simply untrue — but tightening enforcement to match an
     * any-SP publication would make registering a single strict SP silently start
     * refusing every already-working SP that does not sign. A conservative claim
     * costs the strict SP a configuration step (it must be told to sign, which is
     * the same step that put its certificate on file); an over-broad one costs
     * every other SP its logins.
     *
     * With no active SP registered there is nothing being required of anyone, so
     * the answer is `false`. `cbox-id.saml_idp.want_authn_requests_signed` pins it
     * either way for an operator whose policy is IdP-wide.
     *
     * @param  list<ServiceProvider>  $registered
     */
    private function wantAuthnRequestsSigned(array $registered): bool
    {
        $configured = config('cbox-id.saml_idp.want_authn_requests_signed');

        if (is_bool($configured)) {
            return $configured;
        }

        if ($registered === []) {
            return false;
        }

        foreach ($registered as $serviceProvider) {
            if (! $serviceProvider->want_authn_requests_signed) {
                return false;
            }
        }

        return true;
    }

    /**
     * The NameID formats metadata may advertise: the INTERSECTION of what every
     * active SP can be answered under.
     *
     * One IDPSSODescriptor is published to all of them, and an SP treats it as a
     * menu — Shibboleth's `nameIDFormatPrecedence` defaults to the first entry and
     * Salesforce fills its picklist straight from the imported document. Publishing
     * the UNION therefore hands a newly-onboarded SP a sibling's format and answers
     * it with `InvalidNameIDPolicy` for using it. The intersection is by
     * construction a subset of {@see satisfiableNameIdFormats}, which is the same
     * predicate {@see assertNameIdPolicySatisfiable} enforces, so the advertised and
     * accepted sets cannot drift apart.
     *
     * With nothing registered yet, only `unspecified` is honest.
     *
     * @param  list<ServiceProvider>  $registered
     * @return non-empty-list<NameIdFormat>
     */
    private function advertisedNameIdFormats(array $registered): array
    {
        $advertised = null;

        foreach ($registered as $serviceProvider) {
            $satisfiable = $this->satisfiableNameIdFormats($serviceProvider);

            $advertised = $advertised === null
                ? $satisfiable
                : array_values(array_filter(
                    $advertised,
                    static fn (NameIdFormat $format): bool => in_array($format, $satisfiable, true),
                ));
        }

        if ($advertised === null || $advertised === []) {
            return [NameIdFormat::Unspecified];
        }

        return $advertised;
    }

    /**
     * The NameID formats an AuthnRequest addressed to `$serviceProvider` may ask
     * for and be answered under: the SP's OWN registered format — the one the
     * assertion will actually carry — and `unspecified`, which means "IdP, you
     * choose". The SP's format comes first because that is the order an SP reads a
     * precedence list in.
     *
     * @return non-empty-list<NameIdFormat>
     */
    private function satisfiableNameIdFormats(ServiceProvider $serviceProvider): array
    {
        if ($serviceProvider->name_id_format === NameIdFormat::Unspecified) {
            return [NameIdFormat::Unspecified];
        }

        return [$serviceProvider->name_id_format, NameIdFormat::Unspecified];
    }

    /**
     * The SPs registered in this environment that are currently active.
     *
     * @return list<ServiceProvider>
     */
    private function activeServiceProviders(): array
    {
        $active = [];

        foreach ($this->serviceProviders->all() as $serviceProvider) {
            if ($serviceProvider->isActive()) {
                $active[] = $serviceProvider;
            }
        }

        return $active;
    }

    public function parseAuthnRequest(
        string $samlRequest,
        ?string $relayState = null,
        ?string $signature = null,
        ?string $sigAlg = null,
        bool $fromRedirectBinding = true,
        ?string $rawQueryString = null,
    ): AuthnRequest {
        $parsed = $this->parser->parse($samlRequest, $fromRedirectBinding);

        // Deny-by-default: the issuer must be a registered, ACTIVE SP.
        $serviceProvider = $this->serviceProviders->findActiveByEntityId($parsed->issuer);
        if ($serviceProvider === null) {
            throw UnknownServiceProvider::forEntityId($parsed->issuer);
        }

        // ACS pinning: a request MAY carry an AssertionConsumerServiceURL, but it
        // must equal the registered ACS exactly. This is the open-redirect defense —
        // a request that asks us to send the assertion somewhere else is refused.
        if ($parsed->assertionConsumerServiceUrl !== null
            && ! hash_equals($serviceProvider->acs_url, $parsed->assertionConsumerServiceUrl)) {
            throw InvalidAuthnRequest::make('AssertionConsumerServiceURL does not match the registered ACS');
        }

        // Signature policy.
        if ($serviceProvider->want_authn_requests_signed) {
            $this->verifyRequestSignature($serviceProvider, $parsed, $samlRequest, $relayState, $signature, $sigAlg, $fromRedirectBinding, $rawQueryString);
        }

        $signed = $fromRedirectBinding ? ($signature !== null && $signature !== '') : $parsed->hasSignature;

        // From here on the request has cleared every trust gate, so a refusal can
        // be reported to the SP in SAML rather than as an opaque HTTP error.
        $this->assertAddressedToUs($parsed, $serviceProvider, $signed, $relayState);
        $this->assertFresh($parsed, $serviceProvider, $relayState);
        $this->assertNameIdPolicySatisfiable($parsed, $serviceProvider, $relayState);

        return new AuthnRequest(
            id: $parsed->id,
            spEntityId: $serviceProvider->entity_id,
            serviceProviderId: $serviceProvider->id,
            acsUrl: $serviceProvider->acs_url,
            requestedNameIdFormat: $parsed->nameIdFormat,
            relayState: $relayState,
        );
    }

    /**
     * `Destination` binds a request to the endpoint it was meant for. SAML core
     * §3.2.1 makes it a MUST on any signed message, and validating it is what stops
     * a request captured at one endpoint (or one tenant's IdP) being replayed at
     * another.
     *
     * SAML bindings §3.4.5.2 defines the comparison against "the location at which
     * the message has been received", which is NOT the same string as the endpoint
     * we currently publish — see {@see ReceivedEndpoint} for why the two legitimately
     * diverge and why accepting either is the conformant answer.
     */
    private function assertAddressedToUs(
        ParsedAuthnRequest $parsed,
        ServiceProvider $serviceProvider,
        bool $signed,
        ?string $relayState,
    ): void {
        $destination = $parsed->destination;

        if ($destination === null) {
            if ($signed) {
                throw $this->reject(
                    'a signed AuthnRequest must carry a Destination',
                    $parsed,
                    $serviceProvider,
                    $relayState,
                    SamlStatusCode::Requester,
                    SamlStatusCode::RequestDenied,
                );
            }

            return;
        }

        if (! ReceivedEndpoint::addresses($destination, IdpDescriptor::ssoUrl())) {
            throw $this->reject(
                'Destination does not address this SingleSignOnService endpoint',
                $parsed,
                $serviceProvider,
                $relayState,
                SamlStatusCode::Requester,
                SamlStatusCode::RequestDenied,
            );
        }
    }

    /**
     * A signature proves who sent a request, never when. Without a freshness bound
     * a captured AuthnRequest is good forever; the single-use burn that closes the
     * replay lives at issuance ({@see issueResponse}), because THIS request is
     * legitimately parsed twice — once before the host's login hand-off and once
     * when the browser comes back with it.
     */
    private function assertFresh(ParsedAuthnRequest $parsed, ServiceProvider $serviceProvider, ?string $relayState): void
    {
        if (! $this->guard->fresh($parsed->issueInstant, self::REQUEST_FRESHNESS_SECONDS)) {
            throw $this->reject(
                'the AuthnRequest is stale or its IssueInstant is missing/unparseable',
                $parsed,
                $serviceProvider,
                $relayState,
                SamlStatusCode::Requester,
                SamlStatusCode::RequestDenied,
            );
        }
    }

    /**
     * A `NameIDPolicy/@Format` we cannot satisfy is answered with
     * `InvalidNameIDPolicy` (SAML core §3.4.1.1), not silently ignored. The IdP
     * emits the SP's REGISTERED format; a request for `unspecified` means "you
     * choose", and anything else would mean labelling the same value with a
     * different format URN — telling Salesforce an email address is a persistent
     * identifier is worse than refusing.
     *
     * The accepted set is {@see satisfiableNameIdFormats} — the same list metadata
     * is derived from, so nothing this refuses can ever have been advertised.
     */
    private function assertNameIdPolicySatisfiable(
        ParsedAuthnRequest $parsed,
        ServiceProvider $serviceProvider,
        ?string $relayState,
    ): void {
        $requested = $parsed->nameIdFormat;

        if ($requested === null || $requested === '') {
            return;
        }

        $format = NameIdFormat::tryFromPolicyUrn($requested);

        if ($format !== null && in_array($format, $this->satisfiableNameIdFormats($serviceProvider), true)) {
            return;
        }

        throw $this->reject(
            'the requested NameIDPolicy Format is not the one registered for this service provider',
            $parsed,
            $serviceProvider,
            $relayState,
            SamlStatusCode::Requester,
            SamlStatusCode::InvalidNameIdPolicy,
        );
    }

    /** A refusal the SP will be told about on its own ACS, in SAML. */
    private function reject(
        string $reason,
        ParsedAuthnRequest $parsed,
        ServiceProvider $serviceProvider,
        ?string $relayState,
        SamlStatusCode $status,
        ?SamlStatusCode $subStatus = null,
    ): InvalidAuthnRequest {
        return InvalidAuthnRequest::reportable($reason, new SamlError(
            spEntityId: $serviceProvider->entity_id,
            acsUrl: $serviceProvider->acs_url,
            status: $status,
            subStatus: $subStatus,
            inResponseTo: $parsed->id,
            relayState: $relayState,
            message: $reason,
        ));
    }

    public function issueErrorResponse(SamlError $error): SamlResponseVo
    {
        // Re-resolve the SP (deny-by-default, exactly as issuance does): an error
        // response is still a document we sign and POST somewhere, so the target
        // must be a currently-registered, active SP's own registered ACS — never a
        // URL carried in the error itself.
        $serviceProvider = $this->serviceProviders->findActiveByEntityId($error->spEntityId);

        if ($serviceProvider === null) {
            throw UnknownServiceProvider::forEntityId($error->spEntityId);
        }

        $xml = $this->assertions->buildStatus(
            material: $this->keyMaterial->active(),
            idpEntityId: IdpDescriptor::entityId(),
            destination: $serviceProvider->acs_url,
            status: $error->status,
            subStatus: $error->subStatus,
            inResponseTo: $error->inResponseTo,
            message: $error->message,
        );

        return new SamlResponseVo(
            xml: $xml,
            encoded: base64_encode($xml),
            acsUrl: $serviceProvider->acs_url,
            relayState: $error->relayState,
        );
    }

    public function issueResponse(AuthnRequest $request, string $subjectId, array $attributes = []): SamlResponseVo
    {
        // Re-resolve the SP at issuance time (deny-by-default a second time): if it
        // was disabled or removed since the request was parsed, refuse.
        $serviceProvider = $this->serviceProviders->findActiveByEntityId($request->spEntityId);
        if ($serviceProvider === null) {
            throw UnknownServiceProvider::forEntityId($request->spEntityId);
        }

        // Single-use: one AuthnRequest buys exactly one assertion. Burning the id
        // HERE rather than at parse time is deliberate — the SSO endpoint parses
        // the same request again when the browser returns from the host's login,
        // and that is not a replay. A second assertion for it would be.
        if (! $this->guard->consume($request->spEntityId, $request->id, self::REQUEST_FRESHNESS_SECONDS)) {
            throw InvalidAuthnRequest::make('the AuthnRequest has already been answered (replay)');
        }

        $material = $this->keyMaterial->active();

        $nameId = $this->resolveNameId($serviceProvider, $subjectId, $attributes);
        $mappedAttributes = $this->mapAttributes($serviceProvider, $attributes);

        // Record what we are about to tell this SP, so Single Logout can resolve a
        // NameID THROUGH the SP that presents it. Without this, SLO took the NameID from
        // a signed LogoutRequest and revoked every session of whoever it resolved to —
        // and a NameID is not a secret, so any registered SP could name any user it had
        // never seen and end their day.
        $sessionIndex = '_'.bin2hex(random_bytes(16));

        SamlIdpSession::query()->create([
            'sp_entity_id' => $serviceProvider->entity_id,
            'subject_id' => $subjectId,
            'name_id' => $nameId,
            'session_index' => $sessionIndex,
            'expires_at' => now()->addSeconds(self::SESSION_RECORD_TTL_SECONDS),
        ]);

        // Re-pin the ACS and audience from the CURRENT registration, never from the
        // request — the assertion always goes to the trusted, registered location.
        $xml = $this->assertions->build(
            material: $material,
            idpEntityId: IdpDescriptor::entityId(),
            acsUrl: $serviceProvider->acs_url,
            audience: $serviceProvider->entity_id,
            nameId: $nameId,
            nameIdFormat: $serviceProvider->name_id_format->value,
            attributes: $mappedAttributes,
            authnContext: AuthnContext::Password,
            inResponseTo: $request->id,
            sessionIndex: $sessionIndex,
        );

        return new SamlResponseVo(
            xml: $xml,
            encoded: base64_encode($xml),
            acsUrl: $serviceProvider->acs_url,
            relayState: $request->relayState,
        );
    }

    /**
     * @param  array<string, string|list<string>>  $attributes
     */
    private function resolveNameId(ServiceProvider $serviceProvider, string $subjectId, array $attributes): string
    {
        // The FORMAT decides what the value may be. This branch did not exist: whatever
        // `name_id_attribute` pointed at was emitted under whichever format the SP was
        // registered with — and that attribute defaults to `email`. So a NameID declared
        // `persistent` was the person's email address, identical at every service
        // provider: PII, and a perfect join key between any two SPs that compare their
        // user lists, which is precisely the correlation §8.3.7 defines the format to
        // prevent. `transient`, which §8.3.8 says MUST NOT be reused, was a stable email
        // forever. The conformance tests asserted the URN strings and never the value,
        // which is why it survived.
        return match ($serviceProvider->name_id_format) {
            NameIdFormat::Persistent => SamlIdpNameId::pairwiseFor($serviceProvider->entity_id, $subjectId),

            // Fresh per assertion. Recorded on the session row by the caller, which is
            // what lets Single Logout resolve it back to a subject exactly once.
            NameIdFormat::Transient => '_'.bin2hex(random_bytes(16)),

            // EmailAddress and Unspecified mean what the SP configured them to mean.
            default => $this->valuesFor($attributes, $serviceProvider->name_id_attribute)[0] ?? $subjectId,
        };
    }

    /**
     * Project the caller's subject/user fields into SAML attributes via the SP's
     * `attribute_mappings` (SAML attribute name => subject field). Only mapped,
     * present fields are emitted; nothing is leaked by default.
     *
     * @param  array<string, string|list<string>>  $attributes
     * @return array<string, list<string>>
     */
    private function mapAttributes(ServiceProvider $serviceProvider, array $attributes): array
    {
        $mapped = [];

        foreach ($serviceProvider->attribute_mappings as $samlName => $subjectField) {
            if ($samlName === '' || $subjectField === '') {
                continue;
            }

            $values = $this->valuesFor($attributes, $subjectField);

            if ($values !== []) {
                $mapped[$samlName] = $values;
            }
        }

        return $mapped;
    }

    /**
     * Normalise a subject field to a list of string values (a scalar becomes a
     * single-element list; a list is filtered to non-empty strings).
     *
     * @param  array<string, string|list<string>>  $attributes
     * @return list<string>
     */
    private function valuesFor(array $attributes, string $field): array
    {
        $value = $attributes[$field] ?? null;

        if (is_string($value)) {
            return $value !== '' ? [$value] : [];
        }

        if (is_array($value)) {
            $values = [];
            foreach ($value as $item) {
                if ($item !== '') {
                    $values[] = $item;
                }
            }

            return $values;
        }

        return [];
    }

    private function verifyRequestSignature(
        ServiceProvider $serviceProvider,
        ParsedAuthnRequest $parsed,
        string $samlRequest,
        ?string $relayState,
        ?string $signature,
        ?string $sigAlg,
        bool $fromRedirectBinding,
        ?string $rawQueryString = null,
    ): void {
        if ($fromRedirectBinding) {
            $this->redirectSignature->verify(
                $samlRequest,
                $relayState,
                $signature,
                $sigAlg,
                $serviceProvider->certificate,
                $rawQueryString,
            );

            return;
        }

        // POST binding: the signature is an embedded XML-DSig over the request.
        if (! $parsed->hasSignature) {
            throw InvalidAuthnRequest::make('a signed AuthnRequest is required but the POSTed request is unsigned');
        }

        if ($serviceProvider->certificate === null || $serviceProvider->certificate === '') {
            throw InvalidAuthnRequest::make('SP has no certificate on file to verify a signed request');
        }

        $this->embeddedSignature->verify($parsed->document, $serviceProvider->certificate, 'AuthnRequest');
    }

    private function certificateBody(string $pem): string
    {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);

        return is_string($body) ? $body : '';
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Contracts\SamlSingleLogout;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Enums\SamlBinding;
use Cbox\Id\SamlIdp\Exceptions\InvalidLogoutRequest;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\Support\EmbeddedSignature;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\Support\LogoutResponseBuilder;
use Cbox\Id\SamlIdp\Support\MessageGuard;
use Cbox\Id\SamlIdp\Support\ReceivedEndpoint;
use Cbox\Id\SamlIdp\Support\RedirectBindingResponseSigner;
use Cbox\Id\SamlIdp\Support\RedirectBindingSignature;
use Cbox\Id\SamlIdp\ValueObjects\LogoutMessage;
use Cbox\Id\SamlIdp\ValueObjects\SamlLogoutOutcome;
use Cbox\Id\SamlIdp\ValueObjects\SamlPostBinding;
use Cbox\Id\SamlIdp\ValueObjects\SamlResponse as SamlResponseVo;
use Cbox\Id\SamlIdp\ValueObjects\SigningMaterial;
use DOMDocument;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * SP-initiated SAML Single Logout, IdP side. A relying SP sends a signed
 * `LogoutRequest` through the user's browser; this verifies it against that SP's
 * registered certificate, then returns a signed `LogoutResponse` to the SP's SLO
 * endpoint so the SP can complete its own logout.
 *
 * BOTH bindings are supported, because both are advertised in our metadata and
 * Okta and ADFS prefer HTTP-POST: a redirect-bound request is authenticated by its
 * detached query signature and answered with a signed redirect; a POST-bound one
 * carries an enveloped XML-DSig (verified by the same XSW-hardened, RSA-SHA256-
 * pinned {@see EmbeddedSignature} the POST-binding AuthnRequest path uses) and is
 * answered with a self-submitting form carrying a signed `LogoutResponse`.
 *
 * Deny-by-default at every step: the SP must be registered AND active, the request
 * MUST be signed and verify (the LogoutRequest is the security boundary — an unsigned
 * one would let anyone force-log-out a session), it must be addressed to this
 * SingleLogoutService endpoint, fresh and unused, and the SP must have registered an
 * SLO endpoint to answer. Parsing is delegated to onelogin
 * (XXE-guarded `loadXML`); the outbound signature to xmlseclibs — no hand-rolled XML
 * or crypto.
 */
class SamlSingleLogoutService implements SamlSingleLogout
{
    /** Reject a LogoutRequest whose IssueInstant is older/newer than this (clock skew). */
    private const FRESHNESS_SECONDS = 300;

    public function __construct(
        private readonly ServiceProviders $serviceProviders,
        private readonly RedirectBindingSignature $inboundSignature,
        private readonly EmbeddedSignature $embeddedSignature,
        private readonly RedirectBindingResponseSigner $responseSigner,
        private readonly LogoutResponseBuilder $responses,
        private readonly IdpKeyMaterial $keyMaterial,
        private readonly MessageGuard $guard,
    ) {}

    public function process(LogoutMessage $message): SamlLogoutOutcome
    {
        $xml = $this->decode($message->samlRequest);

        $spEntityId = $this->parse(static fn (): ?string => LogoutRequest::getIssuer($xml));

        if ($spEntityId === null || $spEntityId === '') {
            throw InvalidLogoutRequest::make('the LogoutRequest has no Issuer');
        }

        $serviceProvider = $this->serviceProviders->findActiveByEntityId($spEntityId);

        if ($serviceProvider === null) {
            throw InvalidLogoutRequest::make('no active service provider is registered for '.$spEntityId);
        }

        // The LogoutRequest is the security boundary — verify its signature against
        // the SP's registered certificate before acting on it, by whichever
        // mechanism its binding uses. A failure surfaces as InvalidAuthnRequest from
        // the shared verifiers; normalize it.
        try {
            $this->verifySignature($message, $serviceProvider, $xml);
        } catch (InvalidLogoutRequest $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw InvalidLogoutRequest::make($exception->getMessage());
        }

        $destination = $serviceProvider->slo_url;

        if ($destination === null || $destination === '') {
            throw InvalidLogoutRequest::make('service provider '.$spEntityId.' has no SingleLogoutService endpoint on file');
        }

        $nameId = $this->parse(static fn () => LogoutRequest::getNameId($xml));
        $requestId = $this->parse(static fn () => LogoutRequest::getID($xml));

        if ($nameId === null || $requestId === null || $requestId === '') {
            throw InvalidLogoutRequest::make('the LogoutRequest is missing a NameID or ID');
        }

        $this->assertAddressedToUs($xml);

        // Even a validly-signed request must be FRESH and used ONCE — otherwise a
        // captured LogoutRequest could be replayed to force a logout at any later time.
        if (! $this->guard->fresh($this->issueInstant($xml), self::FRESHNESS_SECONDS)) {
            throw InvalidLogoutRequest::make('the LogoutRequest is stale or its IssueInstant is unparseable');
        }

        if (! $this->guard->consume($spEntityId, $requestId, self::FRESHNESS_SECONDS)) {
            throw InvalidLogoutRequest::make('the LogoutRequest has already been processed (replay)');
        }

        $responseXml = $this->responses->build(IdpDescriptor::entityId(), $destination, $requestId);
        $material = $this->keyMaterial->active();

        // Answer on the binding the request arrived on — an SP that advertises only
        // HTTP-POST for SLO has nowhere to receive a redirect-bound response.
        if ($message->binding === SamlBinding::Post) {
            return SamlLogoutOutcome::post($spEntityId, $nameId, $this->postForm($responseXml, $destination, $message->relayState, $material));
        }

        return SamlLogoutOutcome::redirect($spEntityId, $nameId, $this->responseSigner->sign(
            destination: $destination,
            xml: $responseXml,
            relayState: $message->relayState,
            privateKeyPem: $material->privateKeyPem,
        ));
    }

    /**
     * Verify the inbound request's signature the way its binding carries it: a
     * detached signature over the query octets (HTTP-Redirect), or an enveloped
     * XML-DSig bound to the LogoutRequest root (HTTP-POST).
     */
    private function verifySignature(LogoutMessage $message, ServiceProvider $serviceProvider, string $xml): void
    {
        if ($message->binding === SamlBinding::Redirect) {
            $this->inboundSignature->verify(
                $message->samlRequest,
                $message->relayState,
                $message->signature,
                $message->sigAlg,
                $serviceProvider->certificate,
            );

            return;
        }

        $certificate = $serviceProvider->certificate;

        if ($certificate === null || $certificate === '') {
            throw InvalidLogoutRequest::make('service provider has no certificate on file to verify a signed LogoutRequest');
        }

        $this->embeddedSignature->verify($this->document($xml), $certificate, 'LogoutRequest');
    }

    /**
     * The LogoutRequest as a DOM, parsed through onelogin's XXE-guarded loader — no
     * hand-rolled XML, and a parse failure is a clean domain refusal.
     */
    private function document(string $xml): DOMDocument
    {
        $document = new DOMDocument;

        try {
            $loaded = SamlUtils::loadXML($document, $xml);
        } catch (Throwable $exception) {
            throw InvalidLogoutRequest::make('malformed or unsafe XML ('.$exception->getMessage().')');
        }

        if (! $loaded instanceof DOMDocument) {
            throw InvalidLogoutRequest::make('the LogoutRequest could not be parsed');
        }

        return $loaded;
    }

    /**
     * A self-submitting form carrying the `LogoutResponse` to the SP's SLO endpoint
     * (SAML bindings §3.5). The POST binding has no detached query signature, so the
     * response is signed IN the document — enveloped RSA-SHA256 XML-DSig, via the
     * same onelogin primitive the assertion path uses.
     */
    private function postForm(string $xml, string $destination, ?string $relayState, SigningMaterial $material): SamlPostBinding
    {
        $signed = SamlUtils::addSign(
            $xml,
            $material->privateKeyPem,
            $material->certificatePem,
            XMLSecurityKey::RSA_SHA256,
            XMLSecurityDSig::SHA256,
        );

        return (new SamlResponseVo(
            xml: $signed,
            encoded: base64_encode($signed),
            acsUrl: $destination,
            relayState: $relayState,
        ))->toPostBinding();
    }

    /**
     * `Destination` binds the request to the endpoint it was meant for. SAML core
     * §3.2.1 makes it a MUST on any SIGNED message and bindings §3.5.5.2 makes
     * verifying it a MUST on receipt — and every LogoutRequest reaching here is
     * required to be signed, so both apply unconditionally. Leaving it unvalidated
     * while the SSO path enforces it meant a LogoutRequest captured at another
     * endpoint (or another tenant's IdP) could be replayed here inside its freshness
     * window to force a logout.
     *
     * Matched the way {@see ReceivedEndpoint} explains: the location the message was
     * received at, or the published SingleLogoutService endpoint.
     */
    private function assertAddressedToUs(string $xml): void
    {
        $destination = trim($this->document($xml)->documentElement?->getAttribute('Destination') ?? '');

        if ($destination === '') {
            throw InvalidLogoutRequest::make('a signed LogoutRequest must carry a Destination');
        }

        if (! ReceivedEndpoint::addresses($destination, IdpDescriptor::sloUrl())) {
            throw InvalidLogoutRequest::make('Destination does not address this SingleLogoutService endpoint');
        }
    }

    /** The LogoutRequest's `IssueInstant`, or null when it carries none. */
    private function issueInstant(string $xml): ?string
    {
        return preg_match('/IssueInstant="([^"]+)"/', $xml, $matches) === 1 ? $matches[1] : null;
    }

    /** Inflate the payload to XML, tolerating an already-decoded (POST-binding) value. */
    private function decode(string $samlRequest): string
    {
        $decoded = base64_decode($samlRequest, true);

        if ($decoded === false) {
            return $samlRequest;
        }

        $inflated = @gzinflate($decoded);

        return $inflated !== false ? $inflated : $decoded;
    }

    /**
     * Run an onelogin parse helper, turning any parse failure (malformed XML, XXE
     * rejection, missing element) into a clean domain refusal rather than a leak.
     *
     * @param  callable(): ?string  $parser
     */
    private function parse(callable $parser): ?string
    {
        try {
            $value = $parser();
        } catch (Throwable) {
            throw InvalidLogoutRequest::make('the LogoutRequest could not be parsed');
        }

        return $value;
    }
}

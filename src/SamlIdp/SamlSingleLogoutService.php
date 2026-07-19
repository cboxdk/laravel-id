<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Contracts\SamlSingleLogout;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Exceptions\InvalidLogoutRequest;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\Support\LogoutResponseBuilder;
use Cbox\Id\SamlIdp\Support\RedirectBindingResponseSigner;
use Cbox\Id\SamlIdp\Support\RedirectBindingSignature;
use Cbox\Id\SamlIdp\ValueObjects\LogoutMessage;
use Cbox\Id\SamlIdp\ValueObjects\SamlLogoutOutcome;
use OneLogin\Saml2\LogoutRequest;
use Throwable;

/**
 * SP-initiated SAML Single Logout, IdP side. A relying SP sends a signed
 * `LogoutRequest` (HTTP-Redirect binding) through the user's browser; this verifies
 * it against that SP's registered certificate, then returns a signed `LogoutResponse`
 * to the SP's SLO endpoint so the SP can complete its own logout.
 *
 * Deny-by-default at every step: the SP must be registered AND active, the request
 * MUST be signed and verify (the LogoutRequest is the security boundary — an unsigned
 * one would let anyone force-log-out a session), and the SP must have registered an
 * SLO endpoint to answer. Parsing is delegated to onelogin (XXE-guarded `loadXML`);
 * the outbound signature to xmlseclibs — no hand-rolled XML or crypto.
 */
final class SamlSingleLogoutService implements SamlSingleLogout
{
    public function __construct(
        private readonly ServiceProviders $serviceProviders,
        private readonly RedirectBindingSignature $inboundSignature,
        private readonly RedirectBindingResponseSigner $responseSigner,
        private readonly LogoutResponseBuilder $responses,
        private readonly IdpKeyMaterial $keyMaterial,
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

        // The LogoutRequest is the security boundary — verify its detached signature
        // against the SP's registered certificate before acting on it. A failure
        // surfaces as InvalidAuthnRequest from the shared verifier; normalize it.
        try {
            $this->inboundSignature->verify(
                $message->samlRequest,
                $message->relayState,
                $message->signature,
                $message->sigAlg,
                $serviceProvider->certificate,
            );
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

        $responseXml = $this->responses->build(IdpDescriptor::entityId(), $destination, $requestId);

        $redirectUrl = $this->responseSigner->sign(
            destination: $destination,
            xml: $responseXml,
            relayState: $message->relayState,
            privateKeyPem: $this->keyMaterial->active()->privateKeyPem,
        );

        return new SamlLogoutOutcome($nameId, $redirectUrl);
    }

    /** Inflate the redirect-binding payload to XML, tolerating an already-decoded value. */
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

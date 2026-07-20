<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Enums\AuthnContext;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\UnknownServiceProvider;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\Support\AssertionBuilder;
use Cbox\Id\SamlIdp\Support\AuthnRequestParser;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\Support\RedirectBindingSignature;
use Cbox\Id\SamlIdp\ValueObjects\AuthnRequest;
use Cbox\Id\SamlIdp\ValueObjects\ParsedAuthnRequest;
use Cbox\Id\SamlIdp\ValueObjects\SamlResponse as SamlResponseVo;
use DOMDocument;
use DOMElement;
use DOMXPath;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * The SAML 2.0 Identity Provider. Enforces the IdP-side trust policy on top of the
 * vetted signing/verification primitives (xmlseclibs, onelogin): an assertion is
 * only ever minted for a registered, active SP, delivered only to that SP's
 * exact registered ACS, and (when required) only in answer to a signed request.
 */
class SamlIdentityProviderService implements SamlIdentityProvider
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public function __construct(
        private readonly ServiceProviders $serviceProviders,
        private readonly IdpKeyMaterial $keyMaterial,
        private readonly AuthnRequestParser $parser,
        private readonly RedirectBindingSignature $redirectSignature,
        private readonly AssertionBuilder $assertions,
    ) {}

    public function metadata(): string
    {
        $material = $this->keyMaterial->active();
        $certBody = $this->certificateBody($material->certificatePem);

        $entityId = IdpDescriptor::entityId();
        $ssoUrl = IdpDescriptor::ssoUrl();
        $sloUrl = IdpDescriptor::sloUrl();

        $md = 'urn:oasis:names:tc:SAML:2.0:metadata';
        $ds = 'http://www.w3.org/2000/09/xmldsig#';

        $document = new DOMDocument('1.0', 'UTF-8');
        $document->formatOutput = true;

        $entity = $document->createElementNS($md, 'md:EntityDescriptor');
        $entity->setAttribute('entityID', $entityId);
        $document->appendChild($entity);

        $idp = $document->createElementNS($md, 'md:IDPSSODescriptor');
        $idp->setAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $idp->setAttribute('WantAuthnRequestsSigned', 'false');
        $entity->appendChild($idp);

        // Signing key descriptor — the X.509 cert SPs pin to verify our assertions.
        $keyDescriptor = $document->createElementNS($md, 'md:KeyDescriptor');
        $keyDescriptor->setAttribute('use', 'signing');
        $keyInfo = $document->createElementNS($ds, 'ds:KeyInfo');
        $x509Data = $document->createElementNS($ds, 'ds:X509Data');
        $x509Certificate = $document->createElementNS($ds, 'ds:X509Certificate');
        $x509Certificate->appendChild($document->createTextNode($certBody));
        $x509Data->appendChild($x509Certificate);
        $keyInfo->appendChild($x509Data);
        $keyDescriptor->appendChild($keyInfo);
        $idp->appendChild($keyDescriptor);

        // Single Logout endpoints (both bindings).
        foreach (['HTTP-Redirect', 'HTTP-POST'] as $binding) {
            $slo = $document->createElementNS($md, 'md:SingleLogoutService');
            $slo->setAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:'.$binding);
            $slo->setAttribute('Location', $sloUrl);
            $idp->appendChild($slo);
        }

        // Supported NameID formats.
        foreach ([
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified',
        ] as $format) {
            $nameIdFormat = $document->createElementNS($md, 'md:NameIDFormat');
            $nameIdFormat->appendChild($document->createTextNode($format));
            $idp->appendChild($nameIdFormat);
        }

        // Single Sign-On endpoints (both bindings).
        foreach (['HTTP-Redirect', 'HTTP-POST'] as $binding) {
            $sso = $document->createElementNS($md, 'md:SingleSignOnService');
            $sso->setAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:'.$binding);
            $sso->setAttribute('Location', $ssoUrl);
            $idp->appendChild($sso);
        }

        return (string) $document->saveXML();
    }

    public function parseAuthnRequest(
        string $samlRequest,
        ?string $relayState = null,
        ?string $signature = null,
        ?string $sigAlg = null,
        bool $fromRedirectBinding = true,
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
            $this->verifyRequestSignature($serviceProvider, $parsed, $samlRequest, $relayState, $signature, $sigAlg, $fromRedirectBinding);
        }

        return new AuthnRequest(
            id: $parsed->id,
            spEntityId: $serviceProvider->entity_id,
            serviceProviderId: $serviceProvider->id,
            acsUrl: $serviceProvider->acs_url,
            requestedNameIdFormat: $parsed->nameIdFormat,
            relayState: $relayState,
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

        $material = $this->keyMaterial->active();

        $nameId = $this->resolveNameId($serviceProvider, $subjectId, $attributes);
        $mappedAttributes = $this->mapAttributes($serviceProvider, $attributes);

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
        $values = $this->valuesFor($attributes, $serviceProvider->name_id_attribute);

        // Fall back to the opaque subject id when the configured NameID attribute
        // was not supplied — an assertion always has a Subject.
        return $values[0] ?? $subjectId;
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
    ): void {
        if ($fromRedirectBinding) {
            $this->redirectSignature->verify(
                $samlRequest,
                $relayState,
                $signature,
                $sigAlg,
                $serviceProvider->certificate,
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

        $this->verifyEmbeddedSignature($parsed->document, $serviceProvider->certificate);
    }

    /**
     * Verify an enveloped XML-DSig on a POSTed AuthnRequest against the SP cert.
     *
     * The RSA verification is delegated to onelogin's {@see SamlUtils::validateSign()}
     * (xmlseclibs under the hood), but that call only proves *a* signature in the
     * document verifies against the cert — on its own it does NOT prove the signature
     * covers the element the parser actually read. Left alone it accepts a valid
     * signature over a wrapped or duplicated decoy element (XML Signature Wrapping,
     * XSW): xmlseclibs' {@see XMLSecurityDSig::locateSignature()}
     * takes the first `ds:Signature` anywhere in the tree and `validateReference()`
     * resolves the `Reference URI` to any `//*[@ID=…]` node, neither bound to the
     * request root. We close that gap by binding the signature to the root before we
     * trust the verification:
     *
     *  1. the message signature MUST be a single `ds:Signature` that is a direct child
     *     of the AuthnRequest root (an enveloped message signature — not one smuggled
     *     into a nested or wrapped element);
     *  2. its single `Reference` MUST cover that root — an empty URI (whole document)
     *     or `#<root ID>`, never a decoy element elsewhere in the tree; and
     *  3. `validateSign` is PINNED (via its `$xpath` argument) to that exact
     *     root-child signature, so the crypto we verify is the one enveloped in the
     *     root rather than whichever `ds:Signature` appears first in document order.
     *
     * Algorithms are pinned to RSA-SHA256 / SHA-256, matching the redirect binding —
     * onelogin's `validateSign` would otherwise also accept the deprecated SHA-1.
     */
    private function verifyEmbeddedSignature(DOMDocument $document, string $certificate): void
    {
        $root = $document->documentElement;

        if ($root === null) {
            throw InvalidAuthnRequest::make('request signature is invalid');
        }

        $signature = $this->rootChildSignature($document, $root);
        $reference = $this->rootBoundReference($document, $signature, $root);
        $this->assertPinnedSignatureAlgorithms($document, $signature, $reference);

        try {
            // Pin validateSign to the root-child signature located above. Without the
            // $xpath it would locate the first ds:Signature in document order, which a
            // wrapping attacker controls; pinning guarantees the verified crypto is the
            // enveloped signature over the root the parser read.
            $valid = SamlUtils::validateSign(
                $document,
                SamlUtils::formatCert($certificate),
                null,
                'sha1',
                '/samlp:AuthnRequest/ds:Signature',
            );
        } catch (Throwable $exception) {
            throw InvalidAuthnRequest::make('request signature could not be verified ('.$exception->getMessage().')');
        }

        if ($valid !== true) {
            throw InvalidAuthnRequest::make('request signature is invalid');
        }
    }

    /**
     * The message signature: the single `ds:Signature` that is a direct child of the
     * AuthnRequest root. More or fewer than one is rejected — an XSW payload hides its
     * real (decoy-covering) signature deeper in the tree or duplicates it.
     */
    private function rootChildSignature(DOMDocument $document, DOMElement $root): DOMElement
    {
        $nodes = $this->dsigXPath($document)->query('./ds:Signature', $root);

        if ($nodes === false || $nodes->length !== 1) {
            throw InvalidAuthnRequest::make('request must carry exactly one enveloped signature on the request root');
        }

        $signature = $nodes->item(0);

        if (! $signature instanceof DOMElement) {
            throw InvalidAuthnRequest::make('request signature is invalid');
        }

        return $signature;
    }

    /**
     * The signature's single `Reference` must cover the request root — an empty URI
     * (the whole document) or a fragment pointing at the root's own `ID`. Any other
     * target is a signature over a wrapped/duplicated element and is rejected.
     */
    private function rootBoundReference(DOMDocument $document, DOMElement $signature, DOMElement $root): DOMElement
    {
        $nodes = $this->dsigXPath($document)->query('./ds:SignedInfo/ds:Reference', $signature);

        if ($nodes === false || $nodes->length !== 1) {
            throw InvalidAuthnRequest::make('request signature must have exactly one Reference');
        }

        $reference = $nodes->item(0);

        if (! $reference instanceof DOMElement) {
            throw InvalidAuthnRequest::make('request signature is invalid');
        }

        $uri = $reference->getAttribute('URI');
        $rootId = $root->getAttribute('ID');

        if ($uri !== '' && ($rootId === '' || $uri !== '#'.$rootId)) {
            throw InvalidAuthnRequest::make('request signature does not cover the request root (possible signature wrapping)');
        }

        return $reference;
    }

    /**
     * Pin the embedded signature to RSA-SHA256 / SHA-256. onelogin's validateSign
     * accepts RSA-SHA1 too, so without this a SHA-1-signed POST request would pass.
     */
    private function assertPinnedSignatureAlgorithms(DOMDocument $document, DOMElement $signature, DOMElement $reference): void
    {
        $xpath = $this->dsigXPath($document);

        $signatureMethod = $this->attributeOf($xpath, $signature, './ds:SignedInfo/ds:SignatureMethod', 'Algorithm');
        if ($signatureMethod !== XMLSecurityKey::RSA_SHA256) {
            throw InvalidAuthnRequest::make('unsupported signature algorithm (RSA-SHA256 required)');
        }

        $digestMethod = $this->attributeOf($xpath, $reference, './ds:DigestMethod', 'Algorithm');
        if ($digestMethod !== XMLSecurityDSig::SHA256) {
            throw InvalidAuthnRequest::make('unsupported digest algorithm (SHA-256 required)');
        }
    }

    private function attributeOf(DOMXPath $xpath, DOMElement $context, string $expression, string $attribute): string
    {
        $nodes = $xpath->query($expression, $context);

        if ($nodes === false) {
            return '';
        }

        $node = $nodes->item(0);

        return $node instanceof DOMElement ? $node->getAttribute($attribute) : '';
    }

    private function dsigXPath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_PROTOCOL);
        $xpath->registerNamespace('ds', self::NS_DSIG);

        return $xpath;
    }

    private function certificateBody(string $pem): string
    {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);

        return is_string($body) ? $body : '';
    }
}

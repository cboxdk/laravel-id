<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\ValueObjects\ParsedAuthnRequest;
use DOMDocument;
use DOMElement;
use DOMXPath;
use OneLogin\Saml2\Utils as SamlUtils;
use Throwable;

/**
 * Decodes and reads an inbound SAML 2.0 `AuthnRequest`. XML is loaded through
 * onelogin's {@see SamlUtils::loadXML()}, which disables external-entity loading
 * and rejects any DOCTYPE/ENTITY (XXE/XEE defense) — the parser never touches a
 * raw `DOMDocument::loadXML()`. It only reads fields; it makes no trust decision.
 */
class AuthnRequestParser
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * @param  bool  $fromRedirectBinding  redirect-binding payloads are base64 +
     *                                     DEFLATE; POST-binding payloads are base64 only
     */
    public function parse(string $samlRequest, bool $fromRedirectBinding): ParsedAuthnRequest
    {
        $xml = $this->decode($samlRequest, $fromRedirectBinding);

        $document = new DOMDocument;

        try {
            $loaded = SamlUtils::loadXML($document, $xml);
        } catch (Throwable $exception) {
            // Utils::loadXML throws on DOCTYPE/ENTITY — surface it as a rejection.
            throw InvalidAuthnRequest::make('malformed or unsafe XML ('.$exception->getMessage().')');
        }

        if (! $loaded instanceof DOMDocument || $document->documentElement === null) {
            throw InvalidAuthnRequest::make('request XML could not be parsed');
        }

        $root = $document->documentElement;

        if ($root->namespaceURI !== self::NS_PROTOCOL || $root->localName !== 'AuthnRequest') {
            throw InvalidAuthnRequest::make('root element is not a samlp:AuthnRequest');
        }

        $id = $root->getAttribute('ID');
        if ($id === '') {
            throw InvalidAuthnRequest::make('request has no ID');
        }

        $issuer = $this->issuer($document, $root);
        if ($issuer === null) {
            throw InvalidAuthnRequest::make('request has no Issuer');
        }

        $acs = $root->getAttribute('AssertionConsumerServiceURL');

        return new ParsedAuthnRequest(
            id: $id,
            issuer: $issuer,
            assertionConsumerServiceUrl: $acs !== '' ? $acs : null,
            nameIdFormat: $this->nameIdFormat($document, $root),
            hasSignature: $this->hasEmbeddedSignature($document, $root),
            document: $document,
        );
    }

    private function decode(string $samlRequest, bool $fromRedirectBinding): string
    {
        $decoded = base64_decode($samlRequest, true);

        if (! is_string($decoded) || $decoded === '') {
            throw InvalidAuthnRequest::make('request is not valid base64');
        }

        if (! $fromRedirectBinding) {
            return $decoded;
        }

        // Redirect binding: the request is raw-DEFLATE compressed. gzinflate emits a
        // warning and returns false on bad input, so suppress and check explicitly.
        $inflated = @gzinflate($decoded);

        if (! is_string($inflated) || $inflated === '') {
            throw InvalidAuthnRequest::make('redirect-binding request could not be inflated');
        }

        return $inflated;
    }

    private function issuer(DOMDocument $document, DOMElement $root): ?string
    {
        $issuer = $this->query($document, $root, './saml:Issuer');

        if ($issuer === null) {
            return null;
        }

        $value = trim($issuer->textContent);

        return $value !== '' ? $value : null;
    }

    private function nameIdFormat(DOMDocument $document, DOMElement $root): ?string
    {
        $policy = $this->query($document, $root, './samlp:NameIDPolicy');

        if (! $policy instanceof DOMElement) {
            return null;
        }

        $format = $policy->getAttribute('Format');

        return $format !== '' ? $format : null;
    }

    /**
     * A ds:Signature that is a direct child of the AuthnRequest root (an embedded,
     * POST-binding message signature). We deliberately look only at the top level,
     * not anywhere in the tree, so a signature smuggled into an unrelated element
     * is not mistaken for a message signature.
     */
    private function hasEmbeddedSignature(DOMDocument $document, DOMElement $root): bool
    {
        $xpath = $this->xpath($document);
        $nodes = $xpath->query('./ds:Signature', $root);

        return $nodes !== false && $nodes->length > 0;
    }

    private function query(DOMDocument $document, DOMElement $context, string $expression): ?DOMElement
    {
        $nodes = $this->xpath($document)->query($expression, $context);

        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        $node = $nodes->item(0);

        return $node instanceof DOMElement ? $node : null;
    }

    private function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', self::NS_PROTOCOL);
        $xpath->registerNamespace('saml', self::NS_ASSERTION);
        $xpath->registerNamespace('ds', self::NS_DSIG);

        return $xpath;
    }
}

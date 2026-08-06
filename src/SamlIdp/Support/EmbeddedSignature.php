<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use DOMDocument;
use DOMElement;
use DOMXPath;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * Verifies an enveloped XML-DSig on a POSTed SAML protocol message (an
 * `AuthnRequest` or a `LogoutRequest`) against the sending SP's certificate.
 *
 * The RSA verification is delegated to onelogin's {@see SamlUtils::validateSign()}
 * (xmlseclibs under the hood), but that call only proves *a* signature in the
 * document verifies against the cert — on its own it does NOT prove the signature
 * covers the element the parser actually read. Left alone it accepts a valid
 * signature over a wrapped or duplicated decoy element (XML Signature Wrapping,
 * XSW): xmlseclibs' {@see XMLSecurityDSig::locateSignature()} takes the first
 * `ds:Signature` anywhere in the tree and `validateReference()` resolves the
 * `Reference URI` to any `//*[@ID=…]` node, neither bound to the message root. We
 * close that gap by binding the signature to the root before we trust the
 * verification:
 *
 *  1. the message signature MUST be a single `ds:Signature` that is a direct child
 *     of the message root (an enveloped message signature — not one smuggled into
 *     a nested or wrapped element);
 *  2. its single `Reference` MUST cover that root — an empty URI (whole document)
 *     or `#<root ID>`, never a decoy element elsewhere in the tree; and
 *  3. `validateSign` is PINNED (via its `$xpath` argument) to that exact
 *     root-child signature, so the crypto we verify is the one enveloped in the
 *     root rather than whichever `ds:Signature` appears first in document order.
 *
 * Algorithms are pinned to RSA-SHA256 / SHA-256, matching the redirect binding —
 * onelogin's `validateSign` would otherwise also accept the deprecated SHA-1.
 */
class EmbeddedSignature
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * @param  string  $rootElement  the expected root local name (`AuthnRequest`,
     *                               `LogoutRequest`) — it pins the XPath the signature is located by
     *
     * @throws InvalidAuthnRequest when the signature is absent, unbound, weakly
     *                             signed, or does not verify
     */
    public function verify(DOMDocument $document, string $certificate, string $rootElement): void
    {
        $root = $document->documentElement;

        if ($root === null || $root->localName !== $rootElement) {
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
                '/samlp:'.$rootElement.'/ds:Signature',
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
     * message root. More or fewer than one is rejected — an XSW payload hides its
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
     * The signature's single `Reference` must cover the message root — an empty URI
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
}

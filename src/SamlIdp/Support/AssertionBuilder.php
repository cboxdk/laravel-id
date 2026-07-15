<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\SamlIdp\Enums\AuthnContext;
use Cbox\Id\SamlIdp\ValueObjects\SigningMaterial;
use DOMDocument;
use DOMElement;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Builds and signs a SAML 2.0 Response carrying a signed Assertion.
 *
 * The XML is assembled with DOM (never string concatenation), so every value —
 * NameID, attributes, RelayState-adjacent data — is escaped by the DOM writer and
 * cannot break out of its element or attribute. The cryptography is NOT
 * hand-rolled: the Assertion is signed with xmlseclibs (enveloped signature,
 * exclusive C14N, RSA-SHA256, SHA-256 digest) and the enclosing Response with
 * onelogin's {@see SamlUtils::addSign()} (the same primitives). SHA-1 is never
 * emitted.
 *
 * Signing order matters: the Assertion is signed first, then embedded and the
 * Response signed over it, so neither signature invalidates the other.
 */
final class AssertionBuilder
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    private const CONFIRMATION_BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    private const ATTRIBUTE_NAME_FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /** Assertion / confirmation validity window (seconds). Short — bearer tokens. */
    private const LIFETIME_SECONDS = 300;

    /** Backdate NotBefore to absorb modest clock skew between IdP and SP. */
    private const CLOCK_SKEW_SECONDS = 30;

    /**
     * @param  array<string, list<string>>  $attributes  SAML attribute name => values
     * @return string the signed Response XML
     */
    public function build(
        SigningMaterial $material,
        string $idpEntityId,
        string $acsUrl,
        string $audience,
        string $nameId,
        string $nameIdFormat,
        array $attributes,
        AuthnContext $authnContext,
        ?string $inResponseTo,
    ): string {
        $now = time();
        $issueInstant = $this->instant($now);
        $notBefore = $this->instant($now - self::CLOCK_SKEW_SECONDS);
        $notOnOrAfter = $this->instant($now + self::LIFETIME_SECONDS);
        $sessionIndex = $this->id();

        $document = new DOMDocument('1.0', 'UTF-8');

        $response = $document->createElementNS(self::NS_PROTOCOL, 'samlp:Response');
        $document->appendChild($response);
        $response->setAttribute('ID', $this->id());
        $response->setAttribute('Version', '2.0');
        $response->setAttribute('IssueInstant', $issueInstant);
        $response->setAttribute('Destination', $acsUrl);
        if ($inResponseTo !== null) {
            $response->setAttribute('InResponseTo', $inResponseTo);
        }

        $response->appendChild($this->issuerElement($document, $idpEntityId));

        $status = $document->createElementNS(self::NS_PROTOCOL, 'samlp:Status');
        $statusCode = $document->createElementNS(self::NS_PROTOCOL, 'samlp:StatusCode');
        $statusCode->setAttribute('Value', self::STATUS_SUCCESS);
        $status->appendChild($statusCode);
        $response->appendChild($status);

        $assertion = $this->buildAssertion(
            $document,
            $idpEntityId,
            $acsUrl,
            $audience,
            $nameId,
            $nameIdFormat,
            $attributes,
            $authnContext,
            $inResponseTo,
            $issueInstant,
            $notBefore,
            $notOnOrAfter,
            $sessionIndex,
        );
        $response->appendChild($assertion);

        // 1) Sign the Assertion (the security boundary) in place.
        $this->signAssertion($assertion, $material);

        // 2) Sign the enclosing Response over the already-signed Assertion.
        return SamlUtils::addSign(
            $document,
            $material->privateKeyPem,
            $material->certificatePem,
            XMLSecurityKey::RSA_SHA256,
            XMLSecurityDSig::SHA256,
        );
    }

    /**
     * @param  array<string, list<string>>  $attributes
     */
    private function buildAssertion(
        DOMDocument $document,
        string $idpEntityId,
        string $acsUrl,
        string $audience,
        string $nameId,
        string $nameIdFormat,
        array $attributes,
        AuthnContext $authnContext,
        ?string $inResponseTo,
        string $issueInstant,
        string $notBefore,
        string $notOnOrAfter,
        string $sessionIndex,
    ): DOMElement {
        $assertion = $document->createElementNS(self::NS_ASSERTION, 'saml:Assertion');
        $assertion->setAttribute('ID', $this->id());
        $assertion->setAttribute('Version', '2.0');
        $assertion->setAttribute('IssueInstant', $issueInstant);

        // Issuer must be the first child; the signature is inserted immediately after.
        $assertion->appendChild($this->issuerElement($document, $idpEntityId));

        // Subject + bearer SubjectConfirmation (Recipient = registered ACS,
        // InResponseTo = the request id, short NotOnOrAfter).
        $subject = $document->createElementNS(self::NS_ASSERTION, 'saml:Subject');
        $nameIdElement = $document->createElementNS(self::NS_ASSERTION, 'saml:NameID');
        $nameIdElement->setAttribute('Format', $nameIdFormat);
        $nameIdElement->appendChild($document->createTextNode($nameId));
        $subject->appendChild($nameIdElement);

        $confirmation = $document->createElementNS(self::NS_ASSERTION, 'saml:SubjectConfirmation');
        $confirmation->setAttribute('Method', self::CONFIRMATION_BEARER);
        $confirmationData = $document->createElementNS(self::NS_ASSERTION, 'saml:SubjectConfirmationData');
        $confirmationData->setAttribute('NotOnOrAfter', $notOnOrAfter);
        $confirmationData->setAttribute('Recipient', $acsUrl);
        if ($inResponseTo !== null) {
            $confirmationData->setAttribute('InResponseTo', $inResponseTo);
        }
        $confirmation->appendChild($confirmationData);
        $subject->appendChild($confirmation);
        $assertion->appendChild($subject);

        // Conditions: validity window + audience restriction to the SP EntityID.
        $conditions = $document->createElementNS(self::NS_ASSERTION, 'saml:Conditions');
        $conditions->setAttribute('NotBefore', $notBefore);
        $conditions->setAttribute('NotOnOrAfter', $notOnOrAfter);
        $audienceRestriction = $document->createElementNS(self::NS_ASSERTION, 'saml:AudienceRestriction');
        $audienceElement = $document->createElementNS(self::NS_ASSERTION, 'saml:Audience');
        $audienceElement->appendChild($document->createTextNode($audience));
        $audienceRestriction->appendChild($audienceElement);
        $conditions->appendChild($audienceRestriction);
        $assertion->appendChild($conditions);

        // AuthnStatement.
        $authnStatement = $document->createElementNS(self::NS_ASSERTION, 'saml:AuthnStatement');
        $authnStatement->setAttribute('AuthnInstant', $issueInstant);
        $authnStatement->setAttribute('SessionIndex', $sessionIndex);
        $authnContextElement = $document->createElementNS(self::NS_ASSERTION, 'saml:AuthnContext');
        $classRef = $document->createElementNS(self::NS_ASSERTION, 'saml:AuthnContextClassRef');
        $classRef->appendChild($document->createTextNode($authnContext->value));
        $authnContextElement->appendChild($classRef);
        $authnStatement->appendChild($authnContextElement);
        $assertion->appendChild($authnStatement);

        if ($attributes !== []) {
            $assertion->appendChild($this->attributeStatement($document, $attributes));
        }

        return $assertion;
    }

    /**
     * @param  array<string, list<string>>  $attributes
     */
    private function attributeStatement(DOMDocument $document, array $attributes): DOMElement
    {
        $statement = $document->createElementNS(self::NS_ASSERTION, 'saml:AttributeStatement');

        foreach ($attributes as $name => $values) {
            $attribute = $document->createElementNS(self::NS_ASSERTION, 'saml:Attribute');
            $attribute->setAttribute('Name', $name);
            $attribute->setAttribute('NameFormat', self::ATTRIBUTE_NAME_FORMAT);

            foreach ($values as $value) {
                $attributeValue = $document->createElementNS(self::NS_ASSERTION, 'saml:AttributeValue');
                $attributeValue->appendChild($document->createTextNode($value));
                $attribute->appendChild($attributeValue);
            }

            $statement->appendChild($attribute);
        }

        return $statement;
    }

    private function issuerElement(DOMDocument $document, string $idpEntityId): DOMElement
    {
        $issuer = $document->createElementNS(self::NS_ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($idpEntityId));

        return $issuer;
    }

    /**
     * Sign the Assertion element in place: enveloped signature, exclusive C14N,
     * RSA-SHA256, SHA-256 digest, with the signing certificate in KeyInfo. The
     * signature is inserted right after saml:Issuer (before saml:Subject) so the
     * document stays schema-valid.
     */
    private function signAssertion(DOMElement $assertion, SigningMaterial $material): void
    {
        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        // addReferenceList (array-typed) rather than addReference (DOMDocument-typed
        // in the library stub) so the DOMElement reference type-checks; both run the
        // same enveloped-signature + exclusive-C14N reference.
        $dsig->addReferenceList(
            [$assertion],
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false],
        );

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($material->privateKeyPem, false);
        $dsig->sign($key);
        $dsig->add509Cert($material->certificatePem, true);

        // Insert the signature after Issuer, i.e. before Subject (schema order:
        // Issuer, Signature?, Subject, …). Issuer is the first child.
        $issuer = $assertion->firstChild;
        $insertBefore = $issuer?->nextSibling;
        $dsig->insertSignature($assertion, $insertBefore);
    }

    private function id(): string
    {
        return '_'.bin2hex(random_bytes(16));
    }

    private function instant(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }
}

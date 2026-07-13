<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support;

use DOMDocument;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

/**
 * A minimal SAML IdP for tests: a self-signed cert plus a genuinely XML-DSig
 * signed Response. Parameterised so callers can line the audience and ACS
 * recipient up with whatever the connection/route expects.
 */
final class SamlIdp
{
    public string $certPem;

    public string $privatePem;

    public function __construct(public string $entityId = 'https://idp.example.test/metadata')
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'idp.example.test'], $key, ['digest_alg' => 'sha256']);
        $x509 = openssl_csr_sign($csr, null, $key, 3650, ['digest_alg' => 'sha256']);
        openssl_x509_export($x509, $certPem);
        openssl_pkey_export($key, $privatePem);
        $this->certPem = (string) $certPem;
        $this->privatePem = (string) $privatePem;
    }

    public function signedResponse(
        string $nameId,
        string $audience,
        string $recipient,
        string $displayName = 'Alice Example',
        bool $sign = true,
        ?string $inResponseTo = null,
    ): string {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - 300);
        $after = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        $assertionId = '_'.bin2hex(random_bytes(16));
        $responseId = '_'.bin2hex(random_bytes(16));
        $issuer = $this->entityId;
        $inResponseToAttr = $inResponseTo !== null ? ' InResponseTo="'.htmlspecialchars($inResponseTo, ENT_QUOTES).'"' : '';

        $xml = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$responseId}" Version="2.0" IssueInstant="{$now}"{$inResponseToAttr}>
  <saml:Issuer>{$issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{$assertionId}" Version="2.0" IssueInstant="{$now}">
    <saml:Issuer>{$issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{$nameId}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{$after}" Recipient="{$recipient}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{$before}" NotOnOrAfter="{$after}">
      <saml:AudienceRestriction><saml:Audience>{$audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{$now}" SessionIndex="{$assertionId}">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>{$nameId}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="name"><saml:AttributeValue>{$displayName}</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML;

        $doc = new DOMDocument;
        $doc->loadXML($xml);

        if ($sign) {
            $this->signAssertion($doc);
        }

        return base64_encode((string) $doc->saveXML());
    }

    private function signAssertion(DOMDocument $doc): void
    {
        $assertion = $doc->getElementsByTagName('Assertion')->item(0);

        if ($assertion === null) {
            throw new RuntimeException('no assertion to sign');
        }

        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $assertion,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false],
        );

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($this->privatePem, false);
        $dsig->sign($key);
        $dsig->add509Cert($this->certPem, true);

        $subject = $assertion->getElementsByTagName('Subject')->item(0);
        $dsig->insertSignature($assertion, $subject);
    }

    /**
     * Build a signed IdP-initiated `LogoutRequest` for the HTTP-Redirect binding:
     * a deflated+base64 SAMLRequest plus the query-string signature onelogin
     * verifies (`SAMLRequest=…&SigAlg=…` signed with the IdP key).
     *
     * @return array{SAMLRequest: string, SigAlg: string, Signature: string}
     */
    public function signedLogoutRequest(string $nameId, string $destination): array
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $id = '_'.bin2hex(random_bytes(16));

        $xml = <<<XML
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$id}" Version="2.0" IssueInstant="{$now}" Destination="{$destination}">
  <saml:Issuer>{$this->entityId}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{$nameId}</saml:NameID>
</samlp:LogoutRequest>
XML;

        $samlRequest = base64_encode((string) gzdeflate($xml));
        $sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

        // The redirect binding signs the url-encoded query octet-string, in the
        // exact order onelogin reconstructs it for verification.
        $signedQuery = 'SAMLRequest='.urlencode($samlRequest).'&SigAlg='.urlencode($sigAlg);
        openssl_sign($signedQuery, $signature, $this->privatePem, OPENSSL_ALGO_SHA256);

        return [
            'SAMLRequest' => $samlRequest,
            'SigAlg' => $sigAlg,
            'Signature' => base64_encode((string) $signature),
        ];
    }
}

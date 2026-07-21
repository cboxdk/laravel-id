<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\SamlAuthRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

uses(RefreshDatabase::class);

const SP_ENTITY = 'https://sp.example.test/metadata';
const SP_ACS = 'https://sp.example.test/saml/acs';
const IDP_ENTITY = 'https://idp.example.test/metadata';

/**
 * A minimal SAML IdP: self-signed cert + a genuinely XML-DSig-signed Response.
 */
final class SamlIdp
{
    public string $certPem;

    public string $privatePem;

    public function __construct()
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'idp.example.test'], $key, ['digest_alg' => 'sha256']);
        $x509 = openssl_csr_sign($csr, null, $key, 3650, ['digest_alg' => 'sha256']);
        openssl_x509_export($x509, $certPem);
        openssl_pkey_export($key, $privatePem);
        $this->certPem = (string) $certPem;
        $this->privatePem = (string) $privatePem;
    }

    public function response(
        string $nameId = 'alice@corp.com',
        string $audience = SP_ENTITY,
        bool $sign = true,
        bool $tamper = false,
        ?string $inResponseTo = null,
        bool $sha1 = false,
    ): string {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - 300);
        $after = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        $assertionId = '_'.bin2hex(random_bytes(16));
        $responseId = '_'.bin2hex(random_bytes(16));
        $issuer = IDP_ENTITY;
        $recipient = SP_ACS;
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
      <saml:Attribute Name="name"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML;

        $doc = new DOMDocument;
        $doc->loadXML($xml);

        if ($sign) {
            $this->signAssertion($doc, $sha1);
        }

        $signedXml = (string) $doc->saveXML();

        if ($tamper) {
            // Corrupt one character of the SignatureValue to break verification.
            $signedXml = preg_replace_callback(
                '/(<ds:SignatureValue[^>]*>)([A-Za-z0-9+\/=]{10})/',
                fn (array $m): string => $m[1].strrev($m[2]),
                $signedXml,
                1,
            ) ?? $signedXml;
        }

        return base64_encode($signedXml);
    }

    private function signAssertion(DOMDocument $doc, bool $sha1 = false): void
    {
        $assertion = $doc->getElementsByTagName('Assertion')->item(0);

        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $assertion,
            $sha1 ? XMLSecurityDSig::SHA1 : XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false],
        );

        $key = new XMLSecurityKey($sha1 ? XMLSecurityKey::RSA_SHA1 : XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($this->privatePem, false);
        $dsig->sign($key);
        $dsig->add509Cert($this->certPem, true);

        $subject = $assertion->getElementsByTagName('Subject')->item(0);
        $dsig->insertSignature($assertion, $subject);
    }
}

function samlConnection(SamlIdp $idp): Connection
{
    $connections = app(Connections::class);

    $connection = $connections->create((string) Str::ulid(), ConnectionType::Saml, 'Okta', [
        // This fixture posts an UNSOLICITED assertion (no InResponseTo), which is now
        // opt-in per connection — see SamlAssertionValidator. Enabled here so the test
        // keeps exercising the IdP-initiated path deliberately rather than by default.
        'allow_idp_initiated' => true,
        'idp_entity_id' => IDP_ENTITY,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => SP_ENTITY,
        'sp_acs_url' => SP_ACS,
    ]);
    $connections->activate($connection->organization_id, $connection->id);

    return $connection->refresh();
}

beforeEach(function (): void {
    // onelogin/php-saml validates Recipient against the SP's own URL, derived
    // from the server environment — line it up with the ACS URL.
    $_SERVER['HTTP_HOST'] = 'sp.example.test';
    $_SERVER['SERVER_PORT'] = '443';
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['REQUEST_URI'] = '/saml/acs';
    $_SERVER['SCRIPT_NAME'] = '/saml/acs';
});

it('validates a genuinely signed SAML response into a principal', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    $principal = app(AssertionValidator::class)->validate($connection, $idp->response());

    expect($principal->subject)->toBe('alice@corp.com')
        ->and($principal->email)->toBe('alice@corp.com')
        ->and($principal->name)->toBe('Alice Example')
        ->and($principal->provider)->toBe('saml')
        ->and($principal->connectionId)->toBe($connection->id);
});

it('rejects a SAML response with a tampered signature', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    app(AssertionValidator::class)->validate($connection, $idp->response(tamper: true));
})->throws(InvalidAssertion::class);

it('rejects a SAML response signed with RSA-SHA1 (algorithm downgrade)', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    // A genuinely-signed response, but with the deprecated RSA-SHA1 / SHA-1 pair
    // onelogin still accepts. The RP must pin RSA-SHA256 and refuse it.
    app(AssertionValidator::class)->validate($connection, $idp->response(sha1: true));
})->throws(InvalidAssertion::class);

it('rejects an unsigned SAML response (wantAssertionsSigned)', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    app(AssertionValidator::class)->validate($connection, $idp->response(sign: false));
})->throws(InvalidAssertion::class);

it('rejects a SAML response for the wrong audience', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    app(AssertionValidator::class)->validate($connection, $idp->response(audience: 'https://attacker.test/metadata'));
})->throws(InvalidAssertion::class);

it('rejects a SAML response signed by an untrusted key', function (): void {
    $trustedIdp = new SamlIdp;
    $connection = samlConnection($trustedIdp);

    // A different IdP signs the response; the connection trusts only $trustedIdp.
    $attacker = new SamlIdp;

    app(AssertionValidator::class)->validate($connection, $attacker->response());
})->throws(InvalidAssertion::class);

it('rejects a replayed SAML assertion', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);
    $response = $idp->response();

    app(AssertionValidator::class)->validate($connection, $response); // first use — ok
    app(AssertionValidator::class)->validate($connection, $response); // replay — rejected
})->throws(InvalidAssertion::class);

it('accepts an IdP-initiated response (no InResponseTo)', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    // Unsolicited SSO is a legitimate mode — absent InResponseTo is allowed.
    $principal = app(AssertionValidator::class)->validate($connection, $idp->response());

    expect($principal->subject)->toBe('alice@corp.com');
});

it('rejects a response whose InResponseTo matches no request we issued', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    // The IdP (or an attacker replaying a captured response) asserts an
    // InResponseTo we never minted — unsolicited-response injection.
    app(AssertionValidator::class)->validate(
        $connection,
        $idp->response(inResponseTo: '_forged_'.bin2hex(random_bytes(8))),
    );
})->throws(InvalidAssertion::class);

it('accepts a response answering an outstanding request, then burns it', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    $requestId = '_'.bin2hex(random_bytes(16));
    SamlAuthRequest::query()->create([
        'request_id' => $requestId,
        'connection_id' => $connection->id,
        'expires_at' => now()->addMinutes(10),
    ]);

    $principal = app(AssertionValidator::class)->validate(
        $connection,
        $idp->response(inResponseTo: $requestId),
    );
    expect($principal->subject)->toBe('alice@corp.com');

    // The request is single-use: a second response reusing that id is refused
    // even though its InResponseTo was, at issue time, legitimate.
    app(AssertionValidator::class)->validate(
        $connection,
        $idp->response(inResponseTo: $requestId),
    );
})->throws(InvalidAssertion::class);

it('rejects a request id belonging to a different connection', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    // A valid outstanding request, but bound to some OTHER connection.
    SamlAuthRequest::query()->create([
        'request_id' => $requestId = '_'.bin2hex(random_bytes(16)),
        'connection_id' => 'con_other',
        'expires_at' => now()->addMinutes(10),
    ]);

    app(AssertionValidator::class)->validate($connection, $idp->response(inResponseTo: $requestId));
})->throws(InvalidAssertion::class);

it('rejects a response answering an expired request', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    SamlAuthRequest::query()->create([
        'request_id' => $requestId = '_'.bin2hex(random_bytes(16)),
        'connection_id' => $connection->id,
        'expires_at' => now()->subMinute(),
    ]);

    app(AssertionValidator::class)->validate($connection, $idp->response(inResponseTo: $requestId));
})->throws(InvalidAssertion::class);

/**
 * @group isolation
 *
 * An unsolicited (IdP-initiated) assertion is a login-CSRF sink: an attacker with a
 * legitimate account at the customer's IdP obtains their OWN valid assertion and
 * auto-POSTs it from a page the victim visits. The ACS is necessarily CSRF-exempt, so the
 * victim's browser is issued a session as the ATTACKER, and everything they then create
 * lands in the attacker's account. Assertion replay protection does not help — the
 * attacker never redeems it themselves.
 *
 * So it is opt-in per connection, and off by default.
 */
it('refuses an unsolicited assertion unless the connection opts in', function (): void {
    $idp = new SamlIdp;

    // Same fixture as samlConnection(), MINUS the opt-in.
    $connections = app(Connections::class);
    $connection = $connections->create((string) Str::ulid(), ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => IDP_ENTITY,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => SP_ENTITY,
        'sp_acs_url' => SP_ACS,
    ]);
    $connections->activate($connection->organization_id, $connection->id);

    // A genuinely valid, correctly signed assertion — with NO InResponseTo.
    $response = $idp->response('victim@corp.test');

    expect(fn () => app(AssertionValidator::class)->validate($connection->refresh(), $response))
        ->toThrow(InvalidAssertion::class);
});

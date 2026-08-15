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

/*
 * Pest ignores a file-level `@group` docblock — membership comes only from a `uses()` or
 * a per-test `->group()`. So the 17 files that declared the group this way contributed
 * ZERO tests to `--group=isolation`, including the environment-isolation proof itself,
 * while docs/core-concepts/environments.md tells operators to run exactly that command
 * as the evidence. A selector that silently omits its own load-bearing file is worse than
 * no selector.
 */
uses()->group('isolation');

const FED_SP_ENTITY = 'https://sp.example.test/metadata';
const FED_SP_ACS = 'https://sp.example.test/saml/acs';
const FED_IDP_ENTITY = 'https://idp.example.test/metadata';

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
        string $audience = FED_SP_ENTITY,
        bool $sign = true,
        bool $tamper = false,
        ?string $inResponseTo = null,
        bool $sha1 = false,
        // Split from $sha1 deliberately. The signature method and the digest method are
        // pinned by two SEPARATE checks, but one RSA-SHA1 document trips both at once —
        // so with a single flag either check could be deleted and every test still
        // passed. One of them was, and shipped.
        bool $digestSha1 = false,
        // Drop the AudienceRestriction entirely — the shape php-saml waves through,
        // because it only checks the audience when one is present.
        bool $noAudience = false,
        ?string $wrapAs = null,
        ?string $destination = null,
        // Pinned by the cross-tenant replay test: two unrelated IdPs legitimately
        // choosing the same assertion id is the case the ledger's key must allow.
        ?string $assertionId = null,
    ): string {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - 300);
        $after = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        $assertionId ??= '_'.bin2hex(random_bytes(16));
        $audienceRestriction = $noAudience
            ? ''
            : '<saml:AudienceRestriction><saml:Audience>'.$audience.'</saml:Audience></saml:AudienceRestriction>';
        $responseId = '_'.bin2hex(random_bytes(16));
        $issuer = FED_IDP_ENTITY;
        $recipient = FED_SP_ACS;
        $inResponseToAttr = $inResponseTo !== null ? ' InResponseTo="'.htmlspecialchars($inResponseTo, ENT_QUOTES).'"' : '';
        $destinationAttr = $destination !== null ? ' Destination="'.htmlspecialchars($destination, ENT_QUOTES).'"' : '';

        $xml = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$responseId}" Version="2.0" IssueInstant="{$now}"{$inResponseToAttr}{$destinationAttr}>
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
      {$audienceRestriction}
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
            $this->signAssertion($doc, $sha1, $digestSha1);
        }

        if ($wrapAs !== null) {
            $this->wrapSignedAssertion($doc, $wrapAs);
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

    /**
     * Mount an XML Signature Wrapping attack.
     *
     * The genuine assertion and its signature are left completely INTACT — the signature
     * still verifies — and a forged copy naming the attacker is injected alongside it.
     * The attack wins if the validator verifies one element but reads the subject from
     * another, which is precisely what "the signature was valid" cannot tell you.
     *
     * `$wrapAs` selects the classic placements: 'sibling' puts the forgery first inside
     * the Response so a naive "first Assertion" lookup finds it, while 'nested' hides the
     * genuine signed assertion inside the forgery's own Signature/Object so a document
     * scan still finds a valid signature somewhere.
     */
    private function wrapSignedAssertion(DOMDocument $doc, string $wrapAs): void
    {
        $response = $doc->documentElement;
        $genuine = $doc->getElementsByTagName('Assertion')->item(0);

        if ($response === null || $genuine === null) {
            return;
        }

        // A copy of the signed assertion with the attacker's identity and a fresh ID,
        // stripped of the signature that would no longer cover it.
        $forged = $genuine->cloneNode(true);
        $forgedId = '_'.bin2hex(random_bytes(16));

        if ($forged instanceof DOMElement) {
            $forged->setAttribute('ID', $forgedId);

            foreach (iterator_to_array($forged->getElementsByTagName('Signature')) as $sig) {
                $sig->parentNode?->removeChild($sig);
            }

            foreach (iterator_to_array($forged->getElementsByTagName('NameID')) as $nameId) {
                $nameId->nodeValue = 'attacker@evil.test';
            }

            foreach (iterator_to_array($forged->getElementsByTagName('AttributeValue')) as $value) {
                if (str_contains((string) $value->nodeValue, '@')) {
                    $value->nodeValue = 'attacker@evil.test';
                }
            }
        }

        if ($wrapAs === 'nested') {
            // Tuck the genuine, still-signed assertion inside the forgery's Signature so
            // a validator that merely finds "a valid signature in this document" is
            // satisfied while the forged Subject is the one sitting at the top level.
            $response->removeChild($genuine);
            $object = $doc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Object');
            $object->appendChild($genuine);

            $signature = $doc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Signature');
            $signature->appendChild($object);
            $forged->appendChild($signature);
            $response->appendChild($forged);

            return;
        }

        // Sibling: the forgery goes FIRST, so any "take the first Assertion" read picks
        // the attacker's while the genuine signed one trails behind it.
        $response->insertBefore($forged, $genuine);
    }

    private function signAssertion(DOMDocument $doc, bool $sha1 = false, bool $digestSha1 = false): void
    {
        $assertion = $doc->getElementsByTagName('Assertion')->item(0);

        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $assertion,
            // THE DIGEST FOLLOWS ITS OWN FLAG, and only its own. It used to follow
            // `$sha1` as well, which coupled the two algorithms — so `sha1: true` produced
            // an all-SHA-1 document where the SIGNATURE pin fires first, and deleting that
            // pin left the DIGEST pin throwing the same exception class. Neither pin could
            // be observed alone, which is exactly how the digest check was once deleted
            // and shipped.
            $digestSha1 ? XMLSecurityDSig::SHA1 : XMLSecurityDSig::SHA256,
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
        'idp_entity_id' => FED_IDP_ENTITY,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => FED_SP_ENTITY,
        'sp_acs_url' => FED_SP_ACS,
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

/**
 * XML Signature Wrapping — the attack a "the signature was valid" check cannot catch.
 *
 * The genuine assertion and its signature are untouched and still verify; the attacker
 * merely adds a second, forged assertion naming themselves. The system is only safe if
 * the element whose signature was verified is the SAME element whose Subject is
 * consumed. These lock that binding in so it cannot regress behind a library swap or a
 * strict-mode misconfiguration.
 */
it('refuses a wrapped assertion smuggled alongside the genuine signed one', function (string $placement): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    // Refused outright by our own single-assertion rule, BEFORE any question of which
    // Subject to read arises — the strongest place to stop this, since it removes the
    // ambiguity the attack depends on rather than trying to resolve it correctly.
    expect(fn () => app(AssertionValidator::class)->validate(
        $connection,
        $idp->response(wrapAs: $placement),
    ))->toThrow(InvalidAssertion::class, 'must contain 1 assertion');
})->with(['sibling', 'nested']);

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
    //
    // The MESSAGE is asserted, not just the class: `InvalidAssertion` is the single
    // rejection type on this path, so `->throws(InvalidAssertion::class)` passes for any
    // reason at all — including the digest pin catching what the signature pin was
    // supposed to.
    app(AssertionValidator::class)->validate($connection, $idp->response(sha1: true));
})->throws(InvalidAssertion::class, 'unsupported SAML signature algorithm (RSA-SHA256 required)');

/**
 * RSA-SHA256 signature, SHA-1 digest. A conformant-looking document that is weak where it
 * matters, and the case that isolates the digest pin from the signature pin.
 *
 * This test exists because the digest pin was DELETED — an empty `foreach` left where the
 * check had been — and shipped in a release. Nothing went red: every other SAML test uses
 * an all-SHA-1 document, which trips the signature pin first, so the digest check was
 * never the reason any test passed.
 */
it('rejects a SAML response whose digest is SHA-1 even when the signature is RSA-SHA256', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    expect(fn () => app(AssertionValidator::class)->validate($connection, $idp->response(digestSha1: true)))
        ->toThrow(InvalidAssertion::class, 'digest');
});

/**
 * SAML 2.0 Profiles §4.1.4.2 makes it a MUST that the SP verify the assertion contains an
 * `<AudienceRestriction>` naming it. php-saml checks the audience only when one is
 * PRESENT — `if (!empty($validAudiences))` — so an assertion carrying none skipped the
 * check entirely, and nothing here re-checked it.
 *
 * The consequence where an IdP can be made to emit audience-less assertions (Shibboleth
 * and Keycloak custom mappers, a blanked Okta audience): an assertion that IdP
 * legitimately minted for a DIFFERENT relying party is accepted here as a login.
 * InResponseTo blocks the solicited path, so the exposure is a connection with
 * IdP-initiated sign-in enabled — the configuration that has no other binding between
 * the request and the response.
 */
it('refuses an assertion that names no audience', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    expect(fn () => app(AssertionValidator::class)->validate($connection, $idp->response(noAudience: true)))
        ->toThrow(InvalidAssertion::class, 'no AudienceRestriction');
});

/**
 * And one that names somebody else. "It did not say" and "it said someone else" are the
 * same answer to the only question being asked, so both are refused.
 */
it('refuses an assertion addressed to another service provider', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    expect(fn () => app(AssertionValidator::class)->validate($connection, $idp->response(audience: 'https://someone-else.example/sp')))
        ->toThrow(InvalidAssertion::class);
});

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

/**
 * The replay ledger keyed `assertion_id` GLOBALLY, and an assertion id is only unique
 * within the identity provider that issued it — short and sequential ids are common in
 * the wild. So two customers' IdPs choosing the same id meant the SECOND tenant's
 * perfectly valid login was refused as "assertion replay detected": a cross-tenant
 * denial of service on the sign-in path, and a targetable one, since anyone who can make
 * tenant A consume a chosen id can lock tenant B out of it.
 *
 * The identical bug was fixed one table over for DPoP proofs; this ledger never got the
 * same treatment, and had no test at all.
 */
it('lets two connections consume the same assertion id', function (): void {
    $tenantA = new SamlIdp;
    $tenantB = new SamlIdp;

    $connectionA = samlConnection($tenantA);
    $connectionB = samlConnection($tenantB);

    // The same assertion ID from two unrelated identity providers.
    $sharedId = '_shared-assertion-id';

    app(AssertionValidator::class)->validate($connectionA, $tenantA->response(assertionId: $sharedId));

    // Under the global unique this threw InvalidAssertion('assertion replay detected')
    // and tenant B could not sign in at all.
    $principal = app(AssertionValidator::class)->validate($connectionB, $tenantB->response(assertionId: $sharedId));

    expect($principal)->not->toBeNull();
});

it('still rejects a replay on the SAME connection', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);
    $response = $idp->response(assertionId: '_same-connection-replay');

    app(AssertionValidator::class)->validate($connection, $response);
    app(AssertionValidator::class)->validate($connection, $response);
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
        'idp_entity_id' => FED_IDP_ENTITY,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => FED_SP_ENTITY,
        'sp_acs_url' => FED_SP_ACS,
    ]);
    $connections->activate($connection->organization_id, $connection->id);

    // A genuinely valid, correctly signed assertion — with NO InResponseTo.
    $response = $idp->response('victim@corp.test');

    expect(fn () => app(AssertionValidator::class)->validate($connection->refresh(), $response))
        ->toThrow(InvalidAssertion::class);
});

/**
 * Destination binds a response to the endpoint it was addressed to. php-saml
 * compares it with `strncmp` over the shorter of the two strings unless
 * `destinationStrictlyMatches` is set — so a Destination that merely has our ACS
 * as a PREFIX sails through an otherwise strict validator.
 */
it('rejects a response whose Destination only prefixes the ACS', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    $response = $idp->response(destination: FED_SP_ACS.'/somewhere-else');

    expect(fn () => app(AssertionValidator::class)->validate($connection, $response))
        ->toThrow(InvalidAssertion::class);
});

it('still accepts a response whose Destination is exactly the ACS', function (): void {
    $idp = new SamlIdp;
    $connection = samlConnection($idp);

    $principal = app(AssertionValidator::class)->validate($connection, $idp->response(destination: FED_SP_ACS));

    expect($principal->subject)->toBe('alice@corp.com');
});

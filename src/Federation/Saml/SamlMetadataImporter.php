<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Saml;

use Cbox\Id\Federation\Exceptions\SamlMetadataImportFailed;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Federation\ValueObjects\ImportedIdpMetadata;
use Illuminate\Support\Facades\Http;
use OneLogin\Saml2\IdPMetadataParser;
use Throwable;

/**
 * Turns an enterprise IdP's SAML 2.0 metadata (Okta, Entra, Ping, ADFS…) into a
 * connection prefill, so an admin pastes one XML document — or a metadata URL —
 * instead of hand-copying the entity id, SSO URL and signing certificate (the
 * classic source of onboarding typos).
 *
 * Honest-crypto: the XML is parsed by the vetted onelogin/php-saml
 * {@see IdPMetadataParser}, not a hand-rolled DOM walk. Only the IdP half is
 * extracted; the platform still generates the SP half and the admin still confirms
 * before the connection is created. Remote fetch goes through the same SSRF gate
 * ({@see SafeFederationUrl}, DNS-pinned) as every other admin-configured IdP URL —
 * a metadata URL cannot be aimed at the cloud metadata endpoint or an internal host.
 */
class SamlMetadataImporter
{
    public function fromXml(string $xml): ImportedIdpMetadata
    {
        if (trim($xml) === '') {
            throw SamlMetadataImportFailed::make('the metadata document was empty.');
        }

        try {
            $parsed = IdPMetadataParser::parseXML($xml);
        } catch (Throwable $e) {
            throw SamlMetadataImportFailed::make($e->getMessage());
        }

        $rawIdp = $parsed['idp'] ?? null;

        if (! is_array($rawIdp)) {
            throw SamlMetadataImportFailed::make('no IDPSSODescriptor was found in the document.');
        }

        $idp = [];
        foreach ($rawIdp as $key => $value) {
            if (is_string($key)) {
                $idp[$key] = $value;
            }
        }

        $metadata = new ImportedIdpMetadata(
            entityId: $this->string($idp, 'entityId'),
            ssoUrl: $this->nestedUrl($idp, 'singleSignOnService'),
            x509cert: $this->certificate($idp),
            sloUrl: $this->optionalNestedUrl($idp, 'singleLogoutService'),
        );

        if (! $metadata->isComplete()) {
            throw SamlMetadataImportFailed::make('the metadata is missing an entity id, SSO URL, or signing certificate.');
        }

        return $metadata;
    }

    /**
     * Fetch a metadata document from a URL (SSRF-guarded, DNS-pinned) and parse it.
     *
     * @throws UnsafeFederationUrl when the URL resolves to a non-public destination
     */
    public function fromUrl(string $url): ImportedIdpMetadata
    {
        $pinned = SafeFederationUrl::pinnedOptions($url);

        try {
            $response = Http::withOptions($pinned)->timeout(10)->get($url);
        } catch (Throwable $e) {
            throw SamlMetadataImportFailed::make('could not fetch the metadata URL: '.$e->getMessage());
        }

        if (! $response->successful()) {
            throw SamlMetadataImportFailed::make("the metadata URL returned HTTP {$response->status()}.");
        }

        return $this->fromXml($response->body());
    }

    /**
     * @param  array<string, mixed>  $idp
     */
    private function string(array $idp, string $key): string
    {
        $value = $idp[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    /**
     * The `singleSignOnService`/`singleLogoutService` node is `['url' => …, 'binding' => …]`.
     *
     * @param  array<string, mixed>  $idp
     */
    private function nestedUrl(array $idp, string $key): string
    {
        $node = $idp[$key] ?? null;

        if (is_array($node) && isset($node['url']) && is_string($node['url'])) {
            return $node['url'];
        }

        return '';
    }

    /**
     * @param  array<string, mixed>  $idp
     */
    private function optionalNestedUrl(array $idp, string $key): ?string
    {
        $url = $this->nestedUrl($idp, $key);

        return $url !== '' ? $url : null;
    }

    /**
     * The parser exposes a single signing cert as `x509cert`, or several as
     * `x509certMulti['signing']`. Prefer the first signing cert; the validator
     * pins signatures to it.
     *
     * @param  array<string, mixed>  $idp
     */
    private function certificate(array $idp): string
    {
        $single = $idp['x509cert'] ?? null;

        if (is_string($single) && $single !== '') {
            return $single;
        }

        $multi = $idp['x509certMulti'] ?? null;

        if (is_array($multi)) {
            $signing = $multi['signing'] ?? null;

            if (is_array($signing) && isset($signing[0]) && is_string($signing[0])) {
                return $signing[0];
            }
        }

        return '';
    }
}

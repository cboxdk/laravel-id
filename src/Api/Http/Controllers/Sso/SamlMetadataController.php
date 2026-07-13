<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Saml\SamlSettings;
use Illuminate\Http\Response;
use Throwable;

/**
 * Publishes this SP's SAML 2.0 metadata for a connection (SAML metadata spec §2).
 * An IdP administrator points their tooling at this URL to import the entityID,
 * the ACS endpoint and the SLO endpoint during connector setup — removing the
 * hand-copying that causes misconfiguration. Public by design: metadata is not
 * secret and contains no credentials.
 */
final class SamlMetadataController
{
    public function __construct(private readonly Connections $connections) {}

    public function __invoke(string $connection): Response
    {
        $model = $this->connections->byId($connection);

        if ($model === null || $model->type !== ConnectionType::Saml) {
            return new Response('Unknown SAML connection.', 404);
        }

        try {
            $settings = SamlSettings::for($this->connections->config($model));
            $errors = $settings->validateMetadata($xml = $settings->getSPMetadata());
        } catch (Throwable) {
            return new Response('SAML connection is not fully configured.', 422);
        }

        if ($errors !== []) {
            return new Response('Generated metadata is invalid: '.implode(', ', array_filter($errors, 'is_string')), 500);
        }

        return new Response($xml, 200, [
            'Content-Type' => 'application/samlmetadata+xml',
            'Content-Disposition' => 'attachment; filename="cbox-id-sp-metadata.xml"',
        ]);
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Exceptions\InvalidManifest;
use Cbox\Id\AccessControl\Exceptions\ManifestFetchFailed;
use Cbox\Id\AccessControl\Exceptions\UnsafeManifestUrl;
use Cbox\Id\AccessControl\Manifest\Manifest;

/**
 * Pulls an app's authorization manifest from a URL it publishes (the well-known
 * transport), through the SSRF guard, and parses it into a {@see Manifest}.
 */
interface ManifestFetcher
{
    /**
     * @throws UnsafeManifestUrl the URL failed the SSRF guard
     * @throws ManifestFetchFailed the fetch failed or returned non-JSON
     * @throws InvalidManifest the document was malformed
     */
    public function fetch(string $url): Manifest;
}

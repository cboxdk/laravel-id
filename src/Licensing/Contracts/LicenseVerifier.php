<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Contracts;

use Cbox\Id\Licensing\Exceptions\LicenseException;
use Cbox\Id\Licensing\ValueObjects\License;

/**
 * Verifies an on-prem license token offline (no network) against a bundled public
 * key, and returns the decoded {@see License}. Any failure — malformed, wrong
 * signature, not-yet-valid, or expired — throws, and is treated as "unlicensed".
 */
interface LicenseVerifier
{
    /**
     * @throws LicenseException
     */
    public function verify(string $token): License;
}

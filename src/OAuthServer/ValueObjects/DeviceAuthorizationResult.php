<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The device-authorization response (RFC 8628 §3.2). `deviceCode` is the raw
 * polling secret returned once; only its hash is stored.
 */
readonly class DeviceAuthorizationResult
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $deviceCode,
        public string $userCode,
        public string $verificationUri,
        public string $verificationUriComplete,
        public int $expiresIn,
        public int $interval,
        public array $scopes,
    ) {}
}

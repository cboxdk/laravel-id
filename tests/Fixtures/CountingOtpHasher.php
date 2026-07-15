<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Otp\Contracts\OtpHasher;

/**
 * Decorates a real {@see OtpHasher} and records every verify() call, so a test can
 * PROVE the constant-time compare runs on every path — including the miss path
 * (where it must compare against the decoy) — rather than asserting it by comment.
 */
class CountingOtpHasher implements OtpHasher
{
    public int $verifyCalls = 0;

    /**
     * @var list<string>
     */
    public array $verifiedAgainst = [];

    public function __construct(private readonly OtpHasher $inner) {}

    public function hash(string $code): string
    {
        return $this->inner->hash($code);
    }

    public function verify(string $code, string $storedHash): bool
    {
        $this->verifyCalls++;
        $this->verifiedAgainst[] = $storedHash;

        return $this->inner->verify($code, $storedHash);
    }

    public function decoy(): string
    {
        return $this->inner->decoy();
    }
}

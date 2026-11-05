<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\TotpDevice;
use Cbox\Id\Identity\ValueObjects\TotpDeviceEnrollment;

/** Independently named TOTP credentials. Hosts must require recent authentication for writes. */
interface TotpDevices
{
    /** @return list<TotpDevice> Confirmed credentials only; never their secrets. */
    public function devices(string $userId): array;

    /** A fresh secret, shown once. Does not change any existing confirmed credential. */
    public function enrollDevice(string $userId, string $account, string $name, string $issuer = 'Cbox ID'): TotpDeviceEnrollment;

    public function confirmDevice(string $userId, string $deviceId, string $code): bool;

    public function renameDevice(string $userId, string $deviceId, string $name): bool;

    /** Removes one credential; refuses removal of the last confirmed authenticator. */
    public function removeDevice(string $userId, string $deviceId): bool;
}

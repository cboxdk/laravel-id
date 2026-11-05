---
title: Manage authenticator apps
weight: 47
description: Enrol, name and remove independent TOTP credentials without replacing a person's existing apps.
---

# Manage authenticator apps

Resolve `Cbox\Id\Identity\Contracts\TotpDevices` to manage independently named
TOTP credentials. A person can enrol up to ten apps, including unfinished setups.
Existing credentials remain valid after the migration and appear with an empty name;
your UI can display a translated default until the person names them.

```php
use Cbox\Id\Identity\Contracts\TotpDevices;

$apps = app(TotpDevices::class);
$setup = $apps->enrollDevice($userId, $email, 'Personal phone', 'Your service');
// Show $setup->provisioningUri as a QR code and $setup->secret for manual entry.
// Keep $setup->id for this specific enrolment; never persist secrets in browser history.

$confirmed = $apps->confirmDevice($userId, $setup->id, $sixDigitCode);
$confirmedApps = $apps->devices($userId); // id, name and addedAt; no secrets

$apps->renameDevice($userId, $setup->id, 'Spare phone');
$apps->removeDevice($userId, $setup->id);
```

All operations are scoped to the current environment and the specified person. The
host must derive that person from authentication, require recent authentication for
enrolment and removal, and rate-limit code attempts across all of that person's apps.
The package provides no UI or HTTP rate limiter for this contract.

Confirmation expires after ten minutes. Beginning another setup clears expired pending
credentials. An unconfirmed credential can be removed to cancel setup. Each confirmation
consumes its TOTP time step: a login must use a later code. `Mfa::verifyTotp()` accepts
any confirmed app, enforces replay protection, and never accepts a pending credential.

`TotpDeviceRefused::$reason` distinguishes `invalid_name`, `limit_reached`,
`enrolment_busy` and `last_device`. Removing the last confirmed app is refused, even
when another setup is pending. Full MFA reset remains the separate, privileged
`Mfa::disable()` operation. Confirm, rename and remove return false for unknown or
inaccessible credentials; confirmation also returns false for wrong or expired codes.

Recovery codes belong to the person, not to each app. Enrolling, renaming or removing
an app does not change them. A host should show an initial set after first enrolment,
then offer a separate, explicit regeneration action. Serialize first-enrolment
confirmation and initial recovery-code generation so concurrent tabs do not replace
one another's recovery codes.

The older `Mfa::enrollTotp()` / `confirmTotp()` pair remains for a single initial
enrolment. Starting it again after confirmation throws `already_enrolled` rather than
replacing a working key. Use `TotpDevices` for additional apps.

Run the package migrations with the upgrade. They retain the existing encrypted
credentials and replay counters, add names and credential slots, and leave SMS on
slot zero. Rollback is refused while a person has multiple credentials of one type;
it never removes credentials to force the old unique constraint to fit.

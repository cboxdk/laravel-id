<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * A registration ceremony returned a credential_id that is already registered to a
 * different subject. WebAuthn (§7.1 step 22) requires the RP to reject this: the
 * credential_id in a registration response is attacker-controllable (fmt=none/self
 * carries no provenance proof), so a blind upsert would let one user overwrite
 * another user's credential ownership. We refuse rather than reassign.
 */
class CredentialAlreadyRegistered extends RuntimeException
{
    public static function make(string $credentialId): self
    {
        return new self("Credential [{$credentialId}] is already registered to another subject.");
    }
}

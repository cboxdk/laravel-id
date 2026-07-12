<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

/**
 * The security boundary for federation. Implementations (per connection type)
 * wrap a vetted, maintained library — never hand-rolled XML-signature or JWT
 * verification — to validate a raw IdP response against the connection's config.
 *
 * A conforming implementation MUST:
 *  - verify the signature against the connection's configured IdP certificate;
 *  - reject unsigned, tampered, expired, replayed or mis-audienced assertions;
 *  - parse XML with external entities/DTDs disabled (XXE) and guard against
 *    signature-wrapping (XSW).
 *
 * It throws on any validation failure and only returns a principal it fully trusts.
 */
interface AssertionValidator
{
    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal;
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Contracts\UserImport;

/**
 * Knobs for a bulk {@see UserImport} run. The defaults
 * are the safe ones — deny-by-default on credentials, honor the source's
 * verified-email flag, and skip (rather than silently mutate) existing accounts.
 */
final readonly class ImportOptions
{
    /**
     * @param  bool  $upsert  when an email already exists in the environment,
     *                        update it (name/credential/membership/verified) instead
     *                        of skipping the row. Off by default — a re-run is
     *                        idempotent and non-destructive.
     * @param  bool  $markEmailVerified  honor each row's `emailVerified` flag; set
     *                                   false to import everyone as unverified
     *                                   regardless of the source
     * @param  bool  $rejectUnverifiableHashes  DENY-BY-DEFAULT. When true, a
     *                                          `passwordHash` no registered
     *                                          {@see HashVerifier}
     *                                          supports is a per-row ERROR — the
     *                                          user is NOT imported, so you can
     *                                          never import an account that could
     *                                          never log in. Turn off only when a
     *                                          host verifier will be added later.
     * @param  string  $defaultRole  the org membership role for rows that carry no
     *                               explicit role
     * @param  int  $chunkSize  rows per database transaction (batching)
     */
    public function __construct(
        public bool $upsert = false,
        public bool $markEmailVerified = true,
        public bool $rejectUnverifiableHashes = true,
        public string $defaultRole = 'member',
        public int $chunkSize = 500,
    ) {}
}

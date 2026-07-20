<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

/**
 * A single permission an app declares — a `feature:action` key (e.g.
 * `invoices:create`) and a human description shown in the console picker.
 *
 * `tenantAssignable` (default true) is the Frontegg-style guardrail: when false the
 * permission is INTERNAL — the app may bundle it into its own declared roles, but it
 * is hidden from the tenant-admin picker so a customer cannot compose it into a
 * custom role. Lets an app expose a safe subset for self-serve while keeping
 * privileged permissions app-only.
 */
readonly class DeclaredPermission
{
    public function __construct(
        public string $key,
        public ?string $description = null,
        public bool $tenantAssignable = true,
    ) {}
}

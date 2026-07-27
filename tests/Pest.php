<?php

declare(strict_types=1);
use Cbox\Id\Tests\Support\ExternalDriverTestCase;
use Cbox\Id\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(TestCase::class)->in('Feature');

// Bring-your-own-RBAC tests boot under the external access-control driver, so they
// use a base case that selects it before the providers register. Kept in its own
// top-level folder because Pest forbids two different base cases on one file, and a
// nested folder would still be claimed by the blanket binding above.
uses(ExternalDriverTestCase::class)->in('External');

// On a SERVER engine, migrate once per process and wrap each test in a transaction.
//
// Testbench's default is to migrate and roll back around EVERY test. Against sqlite
// `:memory:` that is the only correct option (the database lives in the connection,
// so it cannot outlive one) and it is cheap. Against MySQL or PostgreSQL it is not:
// this package ships ~390 DDL statements, and a real engine takes seconds over each
// create-and-drop pass — measured at over a minute per test on MySQL 8.4, which puts
// a full run in the hours and would make the CI job that guards MySQL support the
// first thing anyone disables.
//
// This is why the trait is applied HERE and conditionally rather than in TestCase:
// the sqlite run — the default, and the one the whole 1357-test baseline was
// established on — keeps byte-identical behaviour, and only the server-engine job
// takes the transactional path.
//
// The cost is that `migrate:fresh` wipes tables rather than calling down(), so the
// rollback path stops being exercised. CBOX_ID_TEST_MIGRATE_EACH=1 opts back out for
// a single file, which is how CI still proves migrations run BOTH ways on a server —
// see the "Migrations up and down" step in .github/workflows/ci.yml.
if (in_array(getenv('DB_CONNECTION'), ['mysql', 'mariadb', 'pgsql'], true)
    && getenv('CBOX_ID_TEST_MIGRATE_EACH') !== '1') {
    uses(RefreshDatabase::class)->in('Feature');
    uses(RefreshDatabase::class)->in('External');
}

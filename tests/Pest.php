<?php

declare(strict_types=1);
use Cbox\Id\Tests\Support\ExternalDriverTestCase;
use Cbox\Id\Tests\TestCase;

uses(TestCase::class)->in('Feature');

// Bring-your-own-RBAC tests boot under the external access-control driver, so they
// use a base case that selects it before the providers register. Kept in its own
// top-level folder because Pest forbids two different base cases on one file, and a
// nested folder would still be claimed by the blanket binding above.
uses(ExternalDriverTestCase::class)->in('External');

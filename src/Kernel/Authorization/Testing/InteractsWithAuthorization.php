<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Testing;

use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;

/**
 * Convenience for wiring relationships and reaching the PDP in tests:
 *
 *     $this->relate(new Relationship('org', 'doc', '1', 'viewer', 'user', 'alice'));
 *     expect($this->pdp()->can('org', Subject::user('alice'), 'viewer', ResourceRef::of('doc', '1')))->toBeTrue();
 */
trait InteractsWithAuthorization
{
    protected function relate(Relationship $relationship): void
    {
        app(RelationshipStore::class)->write($relationship);
    }

    protected function pdp(): PolicyDecisionPoint
    {
        return app(PolicyDecisionPoint::class);
    }
}

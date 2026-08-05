<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\Models\Project;

/**
 * The result of provisioning a new customer: the organization they are, the owner who
 * signs in for them, that owner's membership, their first IdP product, and that product's
 * first environment — an empty, routable realm ready to be configured.
 *
 * FIVE THINGS, and it used to be four with a different first one. There was an `Account`
 * row above the organization carrying the same name and the same status, with its own
 * members and its own roles, and the organization was created beside it and pointed back.
 * Two rows for one customer is two answers to "who may act for them", and the reason this
 * type changed shape is that the two kept disagreeing.
 *
 * The OWNER is split across a subject and a membership deliberately. The subject is who
 * they are — one credential, one identity, the same row a tenant's end user occupies. The
 * membership is what they may do HERE, and only here: the same person can own this
 * organization and be a viewer in another, and neither fact belongs on the identity.
 */
readonly class ProvisionedTenant
{
    public function __construct(
        public Organization $organization,
        public Subject $owner,
        public Membership $membership,
        public Project $project,
        public Environment $environment,
    ) {}
}

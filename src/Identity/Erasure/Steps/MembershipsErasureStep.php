<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure\Steps;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Exceptions\ErasureRefused;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Invitation;

/**
 * Every membership, with the role grants each one carries, and every invitation still
 * addressed to the subject's email.
 *
 * Through {@see Memberships::remove()} rather than a delete, so each removal does what a
 * removal always does: the organization's RBAC grants go with it, `membership.deleted`
 * reaches the organization's webhooks, and outbound SCIM deprovisions per connection.
 *
 * The sole owner of an organization is REFUSED, before anything is removed: an
 * organization nobody owns cannot invite, transfer or archive, and has no way back. The
 * caller transfers ownership first ({@see Memberships::transferOwnership()}).
 */
class MembershipsErasureStep implements ErasureStep
{
    public function __construct(
        private readonly Memberships $memberships,
    ) {}

    public function name(): string
    {
        return 'identity.memberships';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $held = $this->memberships->forUser($request->subjectId);

        $soleOwnerOf = [];

        foreach ($held as $membership) {
            if ($membership->role === MembershipRole::Owner && count($this->memberships->owners($membership->organization_id)) <= 1) {
                $soleOwnerOf[] = $membership->organization_id;
            }
        }

        if ($soleOwnerOf !== []) {
            throw ErasureRefused::lastOwner($soleOwnerOf);
        }

        foreach ($held as $membership) {
            $this->memberships->remove($membership->organization_id, $request->subjectId);
        }

        $invitations = $request->email === null ? 0 : Invitation::query()
            ->whereRaw('lower(email) = ?', [mb_strtolower($request->email)])
            ->toBase()->delete();

        return ErasureStepResult::of($this->name(), [
            'memberships' => $held->count(),
            'invitations' => $invitations,
        ]);
    }
}

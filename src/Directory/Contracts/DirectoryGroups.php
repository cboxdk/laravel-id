<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Api\Support\ScimAttributeSelection;
use Cbox\Id\Directory\Exceptions\UnsupportedDirectoryFilter;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;

/**
 * The directory-group domain: SCIM group listing, lookup, create/replace, PATCH
 * (rename + membership add/remove/replace), and delete. Membership references are
 * resolved to real users of the directory here, so the HTTP layer only validates
 * and maps SCIM to/from these calls.
 */
interface DirectoryGroups
{
    /**
     * A filtered, paginated page of the directory's groups.
     *
     * `$filter` is a SCIM filter expression (empty for none); `$startIndex`/`$count`
     * are the SCIM pagination parameters (null when omitted).
     *
     * `$withMembers` defaults to FALSE and eager-loads membership only when asked.
     * A listing multiplies the cost of membership by the page size, and a page of 200
     * enterprise groups can carry hundreds of thousands of members — see
     * {@see ScimAttributeSelection} for how a client asks for
     * them (`?attributes=members`) and why a single-group read still includes them.
     *
     * @return DirectoryPage<DirectoryGroup>
     *
     * @throws UnsupportedDirectoryFilter
     */
    public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count, bool $withMembers = false): DirectoryPage;

    /**
     * A single group scoped to the directory (members eager-loaded), or null.
     */
    public function find(Directory $directory, string $id): ?DirectoryGroup;

    /**
     * Create a group with the given membership (unknown member ids are ignored).
     *
     * @param  list<string>  $memberIds
     */
    public function create(Directory $directory, string $displayName, ?string $externalId, array $memberIds): DirectoryGroup;

    /**
     * Full replace (PUT): membership becomes exactly `$memberIds`; a null
     * display name or external id leaves that attribute unchanged.
     *
     * @param  list<string>  $memberIds
     */
    public function replace(DirectoryGroup $group, ?string $displayName, ?string $externalId, array $memberIds): DirectoryGroup;

    /**
     * Apply SCIM PATCH operations (rename, and membership add/remove/replace)
     * to a group. Non-array operations are ignored.
     *
     * @param  array<array-key, mixed>  $operations
     */
    public function applyPatch(DirectoryGroup $group, array $operations): DirectoryGroup;

    /**
     * Delete a group and clear its membership.
     */
    public function delete(DirectoryGroup $group): void;
}

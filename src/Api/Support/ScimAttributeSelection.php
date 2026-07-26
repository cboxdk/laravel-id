<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Illuminate\Http\Request;

/**
 * The `attributes` / `excludedAttributes` query parameters of a SCIM request
 * (RFC 7644 §3.9), reduced to the one question this API needs to answer: should
 * this response carry a group's `members`?
 *
 * ## Why members are excluded from LIST by default
 *
 * `GET /Groups` returns a page of up to 200 groups. Serializing every member of
 * every group in that page means an enterprise directory with several 20,000-member
 * groups hydrates hundreds of thousands of models into one response — that is an
 * out-of-memory or a gateway timeout, not a slow page. Entra ID asks for exactly
 * this shape (`?count=200`) on every full sync.
 *
 * RFC 7643 §7 lets a service provider declare an attribute's "returned"
 * characteristic as `request` — returned only when the client asks for it. That is
 * what `members` is here, on LIST only: `GET /Groups/{id}` still returns membership
 * by default, because reading one group is exactly how a client asks for its members,
 * and a client that wants them in a listing can say `?attributes=members`.
 */
final readonly class ScimAttributeSelection
{
    private const MEMBERS = 'members';

    /**
     * @param  list<string>  $requested  lower-cased `attributes` names
     * @param  list<string>  $excluded  lower-cased `excludedAttributes` names
     */
    private function __construct(
        private array $requested,
        private array $excluded,
    ) {}

    public static function fromRequest(Request $request): self
    {
        return new self(
            self::parse($request->query('attributes')),
            self::parse($request->query('excludedAttributes')),
        );
    }

    /**
     * Members are returned unless the client excluded them — the default for reading
     * a SINGLE group.
     */
    public function includeMembers(): bool
    {
        return ! in_array(self::MEMBERS, $this->excluded, true);
    }

    /**
     * Members are returned only when the client asked for them — the default for a
     * LISTING, where the cost is multiplied by the page size.
     */
    public function includeMembersInListing(): bool
    {
        return $this->includeMembers() && in_array(self::MEMBERS, $this->requested, true);
    }

    /**
     * @return list<string>
     */
    private static function parse(mixed $value): array
    {
        if (! is_string($value) || trim($value) === '') {
            return [];
        }

        $names = [];

        foreach (explode(',', $value) as $name) {
            // A client may fully qualify a name
            // (`urn:ietf:params:scim:schemas:core:2.0:Group:members`); only the
            // trailing attribute name is meaningful here.
            $name = strtolower(trim($name));
            $position = strrpos($name, ':');
            $name = $position === false ? $name : substr($name, $position + 1);

            if ($name !== '') {
                $names[] = $name;
            }
        }

        return array_values(array_unique($names));
    }
}

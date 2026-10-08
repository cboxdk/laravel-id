<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Contracts\ScimGroupResources;
use Cbox\Id\Api\Support\ScimAttributeSelection;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 `/Groups` endpoint (RFC 7643 §4.2 / RFC 7644). Supports the group
 * lifecycle IdPs push — create, list (filtered, sorted), read (members included unless
 * excluded; conditional with `If-None-Match`), PUT replace, PATCH rename and membership
 * add/remove/replace, and delete — scoped to the authenticated directory. Every
 * operation is {@see ScimGroupResources}, which `/Bulk` runs too; the controller only
 * reads HTTP.
 */
class GroupController extends ScimController
{
    public function __construct(private readonly ScimGroupResources $groups) {}

    public function index(Request $request): Response
    {
        return $this->render($this->groups->list(
            $this->directory($request),
            $this->search($request),
            ScimAttributeSelection::fromRequest($request),
        ));
    }

    public function store(Request $request): Response
    {
        return $this->render($this->groups->create($this->directory($request), $this->body($request)));
    }

    public function show(Request $request, string $id): Response
    {
        return $this->render($this->groups->show(
            $this->directory($request),
            $id,
            ScimAttributeSelection::fromRequest($request),
            $request->header('If-None-Match'),
        ));
    }

    public function replace(Request $request, string $id): Response
    {
        return $this->render($this->groups->replace($this->directory($request), $id, $this->body($request), $request->header('If-Match')));
    }

    public function patch(Request $request, string $id): Response
    {
        return $this->render($this->groups->patch($this->directory($request), $id, $this->body($request), $request->header('If-Match')));
    }

    public function destroy(Request $request, string $id): Response
    {
        return $this->render($this->groups->delete($this->directory($request), $id, $request->header('If-Match')));
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Contracts\ScimUserResources;
use Cbox\Id\Api\Support\ScimAttributeSelection;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 `/Users` endpoint. Provisioning maps onto the Directory module, which
 * links the local user and — on deactivation/delete — revokes sessions instantly.
 *
 * Covers the full Okta/Entra lifecycle: filtered and sorted list, create, read
 * (conditional, with `If-None-Match`), PATCH, PUT, and delete (both honouring
 * `If-Match`). The controller only reads HTTP; every operation is
 * {@see ScimUserResources}, which `/Bulk` runs too.
 */
class UserController extends ScimController
{
    public function __construct(private readonly ScimUserResources $users) {}

    public function index(Request $request): Response
    {
        return $this->render($this->users->list(
            $this->directory($request),
            $this->search($request),
            ScimAttributeSelection::fromRequest($request),
        ));
    }

    public function store(Request $request): Response
    {
        return $this->render($this->users->create($this->directory($request), $this->body($request)));
    }

    public function show(Request $request, string $id): Response
    {
        return $this->render($this->users->show(
            $this->directory($request),
            $id,
            ScimAttributeSelection::fromRequest($request),
            $request->header('If-None-Match'),
        ));
    }

    public function replace(Request $request, string $id): Response
    {
        return $this->render($this->users->replace($this->directory($request), $id, $this->body($request), $request->header('If-Match')));
    }

    public function patch(Request $request, string $id): Response
    {
        return $this->render($this->users->patch($this->directory($request), $id, $this->body($request), $request->header('If-Match')));
    }

    public function destroy(Request $request, string $id): Response
    {
        return $this->render($this->users->delete($this->directory($request), $id, $request->header('If-Match')));
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Scim;

use Cbox\Id\Api\Contracts\ScimBulkProcessor;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SCIM 2.0 `/Bulk` (RFC 7644 §3.7): many resource operations in one request, run by
 * {@see ScimBulkProcessor} through the same code paths as the single-resource
 * endpoints, under the same bearer token and directory scope.
 */
class BulkController extends ScimController
{
    public function __invoke(Request $request, ScimBulkProcessor $bulk): Response
    {
        $directory = $this->directory($request);

        // §3.7.4: an oversized request is a 413 naming the limit. Measured on the raw
        // body BEFORE it is decoded, so the limit bounds the parse as well as the work.
        $limit = $bulk->maxPayloadSize();
        $size = strlen($request->getContent());

        if ($size > $limit) {
            return $this->error('413', sprintf('The size of the bulk operation exceeds the maxPayloadSize (%d).', $limit));
        }

        return $this->render($bulk->process($directory, $this->body($request)));
    }
}

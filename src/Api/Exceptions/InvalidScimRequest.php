<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Exceptions;

use Cbox\Id\Api\Http\Controllers\Scim\ScimController;
use RuntimeException;

/**
 * A SCIM request this server refuses to interpret, carrying the RFC 7644 §3.12
 * `scimType` keyword the controller must echo back in the Error envelope.
 *
 * Every one of these exists because the alternative is SILENT SUCCESS: the server
 * answers 200 with the unchanged resource, the calling IdP records the write as
 * applied, never retries, and nobody discovers the drift until an auditor does.
 * A 400 with a typed keyword is loud, actionable and retried.
 *
 * {@see UnsupportedScimPath} narrows this to the PATCH-path cases.
 */
class InvalidScimRequest extends RuntimeException
{
    /**
     * @param  string  $scimType  the SCIM error keyword (RFC 7644 §3.12)
     */
    public function __construct(string $message, public readonly string $scimType)
    {
        parent::__construct($message);
    }

    /**
     * RFC 7644 §3.5.2 makes `Operations` mandatory and defines it as "an array of one
     * or more PATCH operations". Degrading anything else to an empty list answered 200
     * with the untouched resource — so a connector whose deactivation body the server
     * could not read had it recorded as applied and never retried, and a terminated
     * employee kept their sessions.
     *
     * This fires only when the member is genuinely absent, empty or not an array. A
     * lower-cased `operations` (or any other casing) is LEGAL SCIM — RFC 7643 §2.1
     * makes attribute names case-insensitive — and is matched, not refused; see
     * {@see ScimController::operations()}.
     */
    public static function missingOperations(): self
    {
        return new self('A PATCH request must carry a non-empty "Operations" array (RFC 7644 §3.5.2).', 'invalidSyntax');
    }

    /**
     * Each member of `Operations` is a PATCH operation object. A scalar in that array
     * cannot be applied, and skipping it is the same silent no-op.
     */
    public static function notAnOperation(): self
    {
        return new self('Every member of "Operations" must be a PATCH operation object (RFC 7644 §3.5.2).', 'invalidSyntax');
    }

    /**
     * RFC 7644 §3.5.2.2: "If 'path' is unspecified, the operation fails with HTTP
     * status code 400 and a 'scimType' error code of 'noTarget'." A `remove` names
     * what to clear; without it there is nothing to remove, and continuing past it
     * answered 200 for an operation the server had not performed.
     */
    public static function noTarget(): self
    {
        return new self('A "remove" operation must specify a "path" (RFC 7644 §3.5.2.2).', 'noTarget');
    }

    /**
     * A boolean attribute whose value is not a SCIM boolean. Refusing beats coercing:
     * coercion turns a typo into a deprovision.
     */
    public static function notABoolean(string $attribute): self
    {
        return new self("The [{$attribute}] attribute must be a boolean (RFC 7643 §2.3.2).", 'invalidValue');
    }
}

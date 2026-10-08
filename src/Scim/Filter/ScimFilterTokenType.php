<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

/**
 * What a {@see ScimFilterToken} is. Keywords (`and`, `not`, `eq`, `true`, …) are not
 * types of their own: they are {@see Word}s whose meaning depends on where the parser
 * finds them, which is exactly how the grammar is written.
 */
enum ScimFilterTokenType
{
    /** An attribute path, operator or keyword. */
    case Word;

    /** A JSON string, already decoded. */
    case String;

    /** A JSON number. */
    case Number;

    case OpenParen;

    case CloseParen;

    case OpenBracket;

    case CloseBracket;

    /** `.name` directly after a closing bracket — `emails[…].value`. */
    case SubAttribute;

    case End;
}

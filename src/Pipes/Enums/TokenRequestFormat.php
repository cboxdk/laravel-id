<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Enums;

/**
 * How a provider's token endpoint wants its request body.
 *
 * RFC 6749 §4.1.3 says form-encoded, and every provider in the catalogue but one agrees.
 * Notion documents a JSON body and nothing else; a form body there is answered with an
 * error that reads like a bad code, not a bad request.
 */
enum TokenRequestFormat: string
{
    case Form = 'form';
    case Json = 'json';
}

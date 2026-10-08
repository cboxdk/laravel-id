<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

use Cbox\Id\Scim\Exceptions\InvalidScimFilter;
use JsonException;

/**
 * Splits a SCIM filter (RFC 7644 §3.4.2.2) or PATCH path (§3.5.2) into tokens.
 *
 * Strings and numbers are JSON (Figure 1: "compValue … ; rules from JSON (RFC 7159)"),
 * so they are matched by the JSON grammar and decoded by PHP's own JSON decoder rather
 * than by a hand-written unescaper: `"O\u0027Malley"`, `"a\"b"` and `"\\"` mean what
 * JSON says they mean, and an invalid escape or a lone surrogate is a syntax error
 * instead of a silently different string.
 *
 * An attribute path is one {@see ScimFilterTokenType::Word} — URN, colons, dots and all
 * (`urn:ietf:params:scim:schemas:core:2.0:User:name.familyName`) — and the parser
 * splits it. Doing it here would mean teaching the lexer that the `.` in `2.0` is not a
 * sub-attribute separator.
 */
class ScimFilterLexer
{
    /** A JSON string literal: no raw control characters, only the escapes JSON defines. */
    private const STRING = '/\G"(?:[^"\\\\\x00-\x1F]|\\\\(?:["\\\\\/bfnrt]|u[0-9a-fA-F]{4}))*"/';

    /** A JSON number. */
    private const NUMBER = '/\G-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/';

    /** An attribute path or keyword: ATTRNAME, optionally URN-qualified, optionally dotted. */
    private const WORD = '/\G[A-Za-z$][A-Za-z0-9_\-$:.]*/';

    /** `.name` straight after `]`. */
    private const SUB_ATTRIBUTE = '/\G\.([A-Za-z$][A-Za-z0-9_\-$]*)/';

    /**
     * @param  bool  $singleQuotes  also accept `'…'` string literals (no escapes). Off for
     *                              filters, which the RFC defines as JSON; on for PATCH
     *                              paths, where identity providers have been seen sending
     *                              `emails[type eq 'work'].value` and this server has
     *                              always understood it.
     * @return list<ScimFilterToken>
     *
     * @throws InvalidScimFilter
     */
    public function tokenize(string $input, bool $singleQuotes = false): array
    {
        $tokens = [];
        $length = strlen($input);
        $offset = 0;

        while ($offset < $length) {
            $char = $input[$offset];

            if (ctype_space($char)) {
                $offset++;

                continue;
            }

            $simple = match ($char) {
                '(' => ScimFilterTokenType::OpenParen,
                ')' => ScimFilterTokenType::CloseParen,
                '[' => ScimFilterTokenType::OpenBracket,
                ']' => ScimFilterTokenType::CloseBracket,
                default => null,
            };

            if ($simple !== null) {
                $tokens[] = new ScimFilterToken($simple, $char, $offset);
                $offset++;

                continue;
            }

            if ($char === '"') {
                [$token, $consumed] = $this->string($input, $offset);
                $tokens[] = $token;
                $offset += $consumed;

                continue;
            }

            if ($char === "'" && $singleQuotes) {
                $end = strpos($input, "'", $offset + 1);

                if ($end === false) {
                    throw InvalidScimFilter::at('Unterminated string', $offset);
                }

                $tokens[] = new ScimFilterToken(ScimFilterTokenType::String, substr($input, $offset + 1, $end - $offset - 1), $offset);
                $offset = $end + 1;

                continue;
            }

            $previous = $tokens === [] ? null : $tokens[count($tokens) - 1];

            if ($char === '.' && $previous?->type === ScimFilterTokenType::CloseBracket
                && preg_match(self::SUB_ATTRIBUTE, $input, $m, 0, $offset) === 1) {
                $tokens[] = new ScimFilterToken(ScimFilterTokenType::SubAttribute, $m[1], $offset);
                $offset += strlen($m[0]);

                continue;
            }

            if (($char === '-' || ctype_digit($char)) && preg_match(self::NUMBER, $input, $m, 0, $offset) === 1) {
                $tokens[] = new ScimFilterToken(ScimFilterTokenType::Number, $this->number($m[0]), $offset);
                $offset += strlen($m[0]);

                continue;
            }

            if (preg_match(self::WORD, $input, $m, 0, $offset) === 1) {
                $tokens[] = new ScimFilterToken(ScimFilterTokenType::Word, $m[0], $offset);
                $offset += strlen($m[0]);

                continue;
            }

            throw InvalidScimFilter::at(sprintf('Unexpected character "%s"', $char), $offset);
        }

        $tokens[] = new ScimFilterToken(ScimFilterTokenType::End, '', $length);

        return $tokens;
    }

    /**
     * The decoded string token, and how many bytes of input it consumed.
     *
     * @return array{ScimFilterToken, int}
     *
     * @throws InvalidScimFilter
     */
    private function string(string $input, int $offset): array
    {
        if (preg_match(self::STRING, $input, $m, 0, $offset) !== 1) {
            throw InvalidScimFilter::at('Malformed string literal', $offset);
        }

        try {
            $decoded = json_decode($m[0], false, 2, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            // A lone surrogate (`"\ud800"`) passes the shape check and fails here.
            throw InvalidScimFilter::at('Malformed string literal', $offset);
        }

        if (! is_string($decoded)) {
            throw InvalidScimFilter::at('Malformed string literal', $offset);
        }

        return [new ScimFilterToken(ScimFilterTokenType::String, $decoded, $offset), strlen($m[0])];
    }

    private function number(string $literal): int|float
    {
        // An integer literal stays an integer while it fits; anything with a fraction
        // or exponent — or too large for an int — is a float, as JSON would decode it.
        if (preg_match('/^-?\d+$/', $literal) === 1) {
            $int = filter_var($literal, FILTER_VALIDATE_INT);

            if (is_int($int)) {
                return $int;
            }
        }

        return (float) $literal;
    }
}

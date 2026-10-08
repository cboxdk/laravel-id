<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Filter;

use Cbox\Id\Scim\Enums\ScimComparisonOperator;
use Cbox\Id\Scim\Enums\ScimLogicalOperator;
use Cbox\Id\Scim\Exceptions\InvalidScimFilter;
use Cbox\Id\Scim\Filter\Nodes\ComparisonNode;
use Cbox\Id\Scim\Filter\Nodes\FilterNode;
use Cbox\Id\Scim\Filter\Nodes\LogicalNode;
use Cbox\Id\Scim\Filter\Nodes\NotNode;
use Cbox\Id\Scim\Filter\Nodes\PresentNode;
use Cbox\Id\Scim\Filter\Nodes\ValuePathNode;

/**
 * A recursive-descent parser for SCIM filters (RFC 7644 §3.4.2.2, Figure 1) and PATCH
 * paths (§3.5.2), producing a typed tree of {@see FilterNode}s.
 *
 * ## Grammar
 *
 * Figure 1's ABNF is left-recursive (`logExp = FILTER SP ("and" / "or") SP FILTER`) and
 * says nothing about precedence; the text below it does — "not" over "and" over "or",
 * grouping above all. So the parser implements the usual stratified form:
 *
 *     filter   = or
 *     or       = and *( "or" and )
 *     and      = unary *( "and" unary )
 *     unary    = "not" "(" filter ")" / "(" filter ")" / attrExp
 *     attrExp  = attrPath ( "pr" / compareOp compValue
 *                         / "[" valFilter "]" [ subAttr ( "pr" / compareOp compValue ) ] )
 *
 * Inside brackets the same grammar applies, except that attribute paths are bare
 * sub-attribute names and brackets cannot nest — a sub-attribute is never itself
 * multi-valued, so a nested value path could only ever be an error.
 *
 * `emails[type eq "work"].value eq "x"` is not Figure 1 (a value path takes no trailing
 * sub-attribute in a FILTER), but it is what Microsoft Entra ID documents sending when
 * user uniqueness is keyed on the work email. It means exactly
 * `emails[type eq "work" and value eq "x"]`, and is parsed to that tree.
 *
 * ## Deny by default
 *
 * A filter arrives in a query string from whoever holds a directory token. The parser
 * bounds the input three ways — total length, nesting depth, and number of comparisons
 * — and refuses anything over, so a hostile `((((((…` cannot exhaust the stack and a
 * ten-thousand-clause `or` cannot become a ten-thousand-clause SQL statement. Every
 * failure is an {@see InvalidScimFilter}; nothing is ever "approximately" parsed.
 */
class ScimFilterParser
{
    public const DEFAULT_MAX_LENGTH = 4096;

    public const DEFAULT_MAX_DEPTH = 16;

    public const DEFAULT_MAX_TERMS = 64;

    /** @var list<ScimFilterToken> */
    private array $tokens = [];

    private int $cursor = 0;

    private int $depth = 0;

    private int $terms = 0;

    public function __construct(
        private readonly ScimFilterLexer $lexer = new ScimFilterLexer,
        private readonly int $maxLength = self::DEFAULT_MAX_LENGTH,
        private readonly int $maxDepth = self::DEFAULT_MAX_DEPTH,
        private readonly int $maxTerms = self::DEFAULT_MAX_TERMS,
    ) {}

    /**
     * Parse a `filter` expression.
     *
     * @throws InvalidScimFilter
     */
    public function parse(string $filter): FilterNode
    {
        $this->begin($filter, false);

        if ($this->peek()->type === ScimFilterTokenType::End) {
            throw InvalidScimFilter::empty();
        }

        $node = $this->orExpression(false);

        $this->expectEnd();

        return $node;
    }

    /**
     * Parse a PATCH operation's `path`: `attrPath / valuePath [subAttr]`.
     *
     * Single-quoted string literals are accepted here (and only here) because identity
     * providers have been seen sending `emails[type eq 'work'].value`, and this server
     * accepted that spelling before it had a parser at all.
     *
     * @throws InvalidScimFilter
     */
    public function parsePath(string $path): ScimPatchPath
    {
        $this->begin($path, true);

        $attribute = $this->attributePath($this->expectWord('an attribute path'), false);
        $filter = null;
        $subAttribute = null;

        if ($this->peek()->type === ScimFilterTokenType::OpenBracket) {
            if ($attribute->subAttribute !== null) {
                throw InvalidScimFilter::at('A value filter must follow an attribute, not a sub-attribute', $this->peek()->position);
            }

            $filter = $this->bracketed();
            $next = $this->peek();

            if ($next->type === ScimFilterTokenType::SubAttribute) {
                $subAttribute = $this->advance()->text();
            }
        }

        $this->expectEnd();

        return new ScimPatchPath($attribute, $filter, $subAttribute);
    }

    /**
     * @throws InvalidScimFilter
     */
    private function begin(string $input, bool $singleQuotes): void
    {
        if (strlen($input) > $this->maxLength) {
            throw InvalidScimFilter::tooLong($this->maxLength);
        }

        $this->tokens = $this->lexer->tokenize($input, $singleQuotes);
        $this->cursor = 0;
        $this->depth = 0;
        $this->terms = 0;
    }

    /**
     * @throws InvalidScimFilter
     */
    private function orExpression(bool $relative): FilterNode
    {
        $node = $this->andExpression($relative);

        while ($this->peek()->isWord('or')) {
            $this->advance();
            $node = new LogicalNode(ScimLogicalOperator::Or, $node, $this->andExpression($relative));
        }

        return $node;
    }

    /**
     * @throws InvalidScimFilter
     */
    private function andExpression(bool $relative): FilterNode
    {
        $node = $this->unary($relative);

        while ($this->peek()->isWord('and')) {
            $this->advance();
            $node = new LogicalNode(ScimLogicalOperator::And, $node, $this->unary($relative));
        }

        return $node;
    }

    /**
     * @throws InvalidScimFilter
     */
    private function unary(bool $relative): FilterNode
    {
        $token = $this->peek();

        // `not` is a keyword only when a parenthesis follows: the grammar has no bare
        // `not attr eq value`, and refusing it is better than guessing its scope.
        if ($token->isWord('not') && $this->peek(1)->type === ScimFilterTokenType::OpenParen) {
            $this->advance();

            return new NotNode($this->parenthesised($relative));
        }

        if ($token->type === ScimFilterTokenType::OpenParen) {
            return $this->parenthesised($relative);
        }

        return $this->attributeExpression($relative);
    }

    /**
     * @throws InvalidScimFilter
     */
    private function parenthesised(bool $relative): FilterNode
    {
        $this->expect(ScimFilterTokenType::OpenParen, '"("');
        $this->enter();

        $node = $this->orExpression($relative);

        $this->expect(ScimFilterTokenType::CloseParen, '")"');
        $this->depth--;

        return $node;
    }

    /**
     * @throws InvalidScimFilter
     */
    private function attributeExpression(bool $relative): FilterNode
    {
        $token = $this->expectWord('an attribute path');

        if (in_array(strtolower($token->text()), ['and', 'or', 'not'], true)) {
            throw InvalidScimFilter::at(sprintf('Expected an attribute path, found "%s"', $token->text()), $token->position);
        }

        $path = $this->attributePath($token, $relative);

        if ($this->peek()->type === ScimFilterTokenType::OpenBracket) {
            if ($relative) {
                throw InvalidScimFilter::at('Value filters cannot be nested', $this->peek()->position);
            }

            if ($path->subAttribute !== null) {
                throw InvalidScimFilter::at('A value filter must follow an attribute, not a sub-attribute', $this->peek()->position);
            }

            $filter = $this->bracketed();
            $next = $this->peek();

            // The Entra form: `emails[type eq "work"].value eq "x"` — folded into the
            // value filter, where it means the same thing.
            if ($next->type === ScimFilterTokenType::SubAttribute) {
                $sub = $this->advance();
                $comparison = $this->comparison(new AttributePath($sub->text()));
                $filter = new LogicalNode(ScimLogicalOperator::And, $filter, $comparison);
            }

            return new ValuePathNode($path, $filter);
        }

        return $this->comparison($path);
    }

    /**
     * `pr`, or an operator and its value, after an attribute path.
     *
     * @throws InvalidScimFilter
     */
    private function comparison(AttributePath $path): FilterNode
    {
        $operator = $this->expectWord('an operator');

        if (++$this->terms > $this->maxTerms) {
            throw InvalidScimFilter::tooManyTerms($this->maxTerms);
        }

        if (strtolower($operator->text()) === 'pr') {
            return new PresentNode($path);
        }

        $parsed = ScimComparisonOperator::tryParse($operator->text())
            ?? throw InvalidScimFilter::at(sprintf('The operator "%s" is not supported', $operator->text()), $operator->position);

        return new ComparisonNode($path, $parsed, $this->value());
    }

    /**
     * A `compValue`: JSON `false`, `null`, `true`, number or string.
     *
     * The three literals are matched without regard to case. JSON spells them in lower
     * case, but the RFC makes every other bare word in a filter case-insensitive and a
     * client writing `active eq True` is not asking for anything else.
     *
     * @throws InvalidScimFilter
     */
    private function value(): string|int|float|bool|null
    {
        $token = $this->advance();

        return match (true) {
            $token->type === ScimFilterTokenType::String => $token->text(),
            $token->type === ScimFilterTokenType::Number && ! is_string($token->value) => $token->value,
            $token->isWord('true') => true,
            $token->isWord('false') => false,
            $token->isWord('null') => null,
            $token->type === ScimFilterTokenType::End => throw InvalidScimFilter::at('Expected a comparison value, found the end of the filter', $token->position),
            // An unquoted word (`externalId eq jyoung`) is not a JSON value. Taking it
            // as a string would make `active eq fasle` a string comparison instead of
            // an error.
            default => throw InvalidScimFilter::at(sprintf('Expected a quoted string, number, true, false or null, found "%s"', $token->text()), $token->position),
        };
    }

    /**
     * `"[" valFilter "]"`.
     *
     * @throws InvalidScimFilter
     */
    private function bracketed(): FilterNode
    {
        $this->expect(ScimFilterTokenType::OpenBracket, '"["');
        $this->enter();

        $filter = $this->orExpression(true);

        $this->expect(ScimFilterTokenType::CloseBracket, '"]"');
        $this->depth--;

        return $filter;
    }

    /**
     * Split an attribute-path word into URN, attribute and sub-attribute.
     *
     * The URN is everything up to the LAST colon — `urn:…:core:2.0:User:userName` — so
     * the dots inside `2.0` never reach the sub-attribute split.
     *
     * @throws InvalidScimFilter
     */
    private function attributePath(ScimFilterToken $token, bool $relative): AttributePath
    {
        $word = $token->text();
        $schema = null;
        $colon = strrpos($word, ':');

        if ($colon !== false) {
            $schema = substr($word, 0, $colon);
            $word = substr($word, $colon + 1);

            if (! str_starts_with(strtolower($schema), 'urn:')) {
                throw InvalidScimFilter::at(sprintf('"%s" is not a schema URN', $schema), $token->position);
            }
        }

        if (preg_match('/^([A-Za-z$][A-Za-z0-9_\-$]*)(?:\.([A-Za-z$][A-Za-z0-9_\-$]*))?$/', $word, $m) !== 1) {
            throw InvalidScimFilter::at(sprintf('"%s" is not an attribute path', $token->text()), $token->position);
        }

        $subAttribute = ($m[2] ?? '') === '' ? null : $m[2];

        // Inside brackets a path names one sub-attribute of the value being tested —
        // `type`, `value`, `primary` — and nothing more.
        if ($relative && ($schema !== null || $subAttribute !== null)) {
            throw InvalidScimFilter::at(sprintf('"%s" must be a plain sub-attribute name inside a value filter', $token->text()), $token->position);
        }

        return new AttributePath($m[1], $subAttribute, $schema);
    }

    /**
     * @throws InvalidScimFilter
     */
    private function enter(): void
    {
        if (++$this->depth > $this->maxDepth) {
            throw InvalidScimFilter::tooDeep($this->maxDepth);
        }
    }

    private function peek(int $ahead = 0): ScimFilterToken
    {
        return $this->tokens[min($this->cursor + $ahead, count($this->tokens) - 1)];
    }

    private function advance(): ScimFilterToken
    {
        $token = $this->peek();

        if ($token->type !== ScimFilterTokenType::End) {
            $this->cursor++;
        }

        return $token;
    }

    /**
     * @throws InvalidScimFilter
     */
    private function expect(ScimFilterTokenType $type, string $description): ScimFilterToken
    {
        $token = $this->advance();

        if ($token->type !== $type) {
            throw InvalidScimFilter::at(sprintf('Expected %s, found %s', $description, $this->describe($token)), $token->position);
        }

        return $token;
    }

    /**
     * @throws InvalidScimFilter
     */
    private function expectWord(string $description): ScimFilterToken
    {
        return $this->expect(ScimFilterTokenType::Word, $description);
    }

    /**
     * @throws InvalidScimFilter
     */
    private function expectEnd(): void
    {
        $token = $this->peek();

        if ($token->type !== ScimFilterTokenType::End) {
            throw InvalidScimFilter::at(sprintf('Unexpected %s', $this->describe($token)), $token->position);
        }
    }

    private function describe(ScimFilterToken $token): string
    {
        return match ($token->type) {
            ScimFilterTokenType::End => 'the end of the input',
            ScimFilterTokenType::String => 'a string',
            ScimFilterTokenType::Number => 'a number',
            default => sprintf('"%s"', $token->text()),
        };
    }
}

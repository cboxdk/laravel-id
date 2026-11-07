<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Exceptions;

use Cbox\Id\Kernel\Authorization\Schema\SchemaError;
use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/**
 * The schema does not parse, or names something it does not define, or subtracts a
 * relation from itself. Every problem found is listed, by line, not just the first.
 */
final class InvalidSchema extends AuthorizationModelException implements HasSourceMessage
{
    use CarriesSourceMessage;

    /**
     * @param  list<SchemaError>  $errors
     */
    public function __construct(public readonly array $errors)
    {
        $parts = array_map(static function (SchemaError $error): SourceMessage {
            $message = $error->source ?? new SourceMessage(':message', ['message' => $error->message]);

            return $error->line > 0 ? new SourceMessage('Line :line: :message', ['line' => $error->line, 'message' => $message]) : $message;
        }, $errors);
        $this->withSourceMessage(new SourceMessage(':messages', ['messages' => $parts]));
        parent::__construct(implode(' ', array_map(static fn (SchemaError $error): string => (string) $error, $errors)));
    }

    public function errorCode(): string
    {
        return 'invalid_schema';
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;

/**
 * One thing wrong with a schema, and the line it is on (0 when it is about the whole).
 */
final readonly class SchemaError
{
    public function __construct(
        public int $line,
        public string $message,
        public ?SourceMessage $source = null,
    ) {}

    public function __toString(): string
    {
        return $this->line > 0 ? "Line {$this->line}: {$this->message}" : $this->message;
    }

    /**
     * @return array{line: int, message: string}
     */
    public function toArray(): array
    {
        return ['line' => $this->line, 'message' => $this->message];
    }
}

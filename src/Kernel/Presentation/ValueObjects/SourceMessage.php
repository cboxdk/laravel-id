<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Presentation\ValueObjects;

/** Source-owned text kept separate from values so a host can localize its UI. */
readonly class SourceMessage
{
    /** @param array<string, string|int|float|self|list<self>> $parameters */
    public function __construct(public string $template, public array $parameters = []) {}

    /** Render the unchanged source text for protocol messages and logs. */
    public function english(): string
    {
        $replace = [];
        foreach ($this->parameters as $name => $value) {
            $replace[':'.$name] = match (true) {
                $value instanceof self => $value->english(),
                is_array($value) => implode(', ', array_map(static fn (self $item): string => $item->english(), $value)),
                default => (string) $value,
            };
        }

        return strtr($this->template, $replace);
    }
}

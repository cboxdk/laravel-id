<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\ValueObjects;

use Illuminate\Validation\ValidationException;
use JsonException;
use stdClass;

/** Top-level keys are atomic; null is a value, deletion is explicit. */
readonly class PropertyPatch
{
    /** @param list<string> $remove */
    public function __construct(public int $version, public stdClass $set = new stdClass, public array $remove = [])
    {
        if ($version < 0) {
            throw ValidationException::withMessages(['version' => 'Use a non-negative version and a list of keys to remove.']);
        }
        foreach ([...array_keys(get_object_vars($set)), ...$remove] as $key) {
            if (! is_string($key) || preg_match('/\A[a-zA-Z][a-zA-Z0-9_.-]{0,127}\z/D', $key) !== 1) {
                throw ValidationException::withMessages(['set' => 'Keys must start with a letter and contain at most 128 letters, digits, dots, underscores or hyphens.']);
            }
        }
        if (array_intersect(array_keys(get_object_vars($set)), $remove) !== []) {
            throw ValidationException::withMessages(['remove' => 'A key cannot be set and removed in the same patch.']);
        }
        self::validateDocument($set);
    }

    public static function validateDocument(stdClass $document): void
    {
        try {
            $json = json_encode($document, JSON_THROW_ON_ERROR, 16);
            // Round-trip rejects non-JSON values and bounds nesting before persistence.
            json_decode($json, false, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw ValidationException::withMessages(['set' => 'Use valid JSON with at most 16 levels.']);
        }
        if (strlen($json) > 16384 || count(get_object_vars($document)) > 100) {
            throw ValidationException::withMessages(['set' => 'A namespace document may contain at most 100 keys and 16 KiB of JSON.']);
        }
    }
}

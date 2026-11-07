<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use InvalidArgumentException;

/**
 * A flag could not be saved as described. `reason` is a stable machine code a console or
 * management API maps to its own refusal; `field` names the input it is about.
 */
class InvalidFeatureFlag extends InvalidArgumentException implements HasSourceMessage
{
    use CarriesSourceMessage;

    private function __construct(string $message, public readonly string $reason, public readonly string $field)
    {
        parent::__construct($message);
    }

    public static function key(string $key): self
    {
        return (new self("The flag key [{$key}] must be 1 to 64 characters: lowercase letters, digits, and `-`, `_` or `.` between them.", 'invalid_key', 'key'))->withSourceMessage(new SourceMessage('The flag key [:key] must be 1 to 64 characters: lowercase letters, digits, and `-`, `_` or `.` between them.', ['key' => $key]));
    }

    public static function keyTaken(string $key): self
    {
        return (new self("A feature flag with the key [{$key}] already exists in this environment.", 'key_taken', 'key'))->withSourceMessage(new SourceMessage('A feature flag with the key [:key] already exists in this environment.', ['key' => $key]));
    }

    public static function description(): self
    {
        return (new self('A flag description is at most 500 characters.', 'invalid_description', 'description'))->withSourceMessage(new SourceMessage('A flag description is at most 500 characters.', []));
    }

    public static function percentage(int $percentage): self
    {
        return (new self("A rollout percentage is 0 to 100, not {$percentage}.", 'invalid_percentage', 'rollout_percentage'))->withSourceMessage(new SourceMessage('A rollout percentage is 0 to 100, not :percentage.', ['percentage' => $percentage]));
    }

    public static function tooManyRules(int $limit): self
    {
        return (new self("A flag holds at most {$limit} user and organization rules. Target an organization, or use a rollout percentage, instead of listing every user.", 'too_many_rules', 'targeting'))->withSourceMessage(new SourceMessage('A flag holds at most :limit user and organization rules. Target an organization, or use a rollout percentage, instead of listing every user.', ['limit' => $limit]));
    }

    /**
     * @param  list<string>  $ids
     */
    public static function unknownOrganizations(array $ids): self
    {
        return (new self('No organization with the id ['.implode(', ', $ids).'] exists in this environment.', 'unknown_organization', 'organizations'))->withSourceMessage(new SourceMessage('No organization with the id [:value1] exists in this environment.', ['value1' => implode(', ', $ids)]));
    }

    /**
     * @param  list<string>  $ids
     */
    public static function unknownUsers(array $ids): self
    {
        return (new self('No user with the id ['.implode(', ', $ids).'] exists in this environment.', 'unknown_user', 'users'))->withSourceMessage(new SourceMessage('No user with the id [:value1] exists in this environment.', ['value1' => implode(', ', $ids)]));
    }
}

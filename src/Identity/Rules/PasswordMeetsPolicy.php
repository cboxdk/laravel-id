<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Rules;

use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * Validates a proposed password against the tenant's effective {@see AuthPolicy}.
 *
 * The policy is enforced at the credential primitive regardless, so this rule is not
 * what makes a weak password impossible — it is what makes the refusal land on the
 * field the person is typing into instead of surfacing as an unhandled exception. Forms
 * that set a password should use it INSTEAD of a hardcoded `min:` rule, which by
 * definition cannot know what the tenant requires.
 */
class PasswordMeetsPolicy implements ValidationRule
{
    public function __construct(
        private readonly PasswordPolicyGuard $guard,
        private readonly ?string $userId = null,
        private readonly ?string $organizationId = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            return;
        }

        try {
            $this->guard->assertAcceptable($value, $this->userId, $this->organizationId);
        } catch (PolicyViolation $violation) {
            $fail($violation->getMessage());
        }
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Rules;

use Cbox\Id\Identity\Contracts\PasswordPolicyGuard;
use Cbox\Id\Identity\Exceptions\PolicyViolation;
use Closure;
use Illuminate\Container\Container;
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

    /**
     * Resolve the guard from the container, so a form can name the rule without also
     * naming its dependency: `new PasswordMeetsPolicy(...)` in a validation array reads
     * as plumbing, and plumbing is what people leave out.
     *
     * Pass the subject when the password is being CHANGED, so the reuse history applies;
     * leave it null when the subject does not exist yet. Pass the organization when the
     * form knows one the subject may not be a member of yet.
     */
    public static function for(?string $userId = null, ?string $organizationId = null): self
    {
        return new self(Container::getInstance()->make(PasswordPolicyGuard::class), $userId, $organizationId);
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            return;
        }

        try {
            // A form legitimately may not know the subject — signup has none yet, and the
            // token-based reset deliberately does not resolve one (doing so would make
            // the page an account-existence oracle). The guard is asked the matching
            // question rather than handed a null and left to guess which case this is.
            $this->userId === null
                ? $this->guard->assertAcceptableForNewSubject($value, $this->organizationId)
                : $this->guard->assertAcceptable($value, $this->userId, $this->organizationId);
        } catch (PolicyViolation $violation) {
            $fail($violation->getMessage());
        }
    }
}

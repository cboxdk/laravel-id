<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * Which sign-in methods are offered in the current environment, and how long its sessions
 * last — the deployment's ceiling and the environment's own choice, combined once.
 *
 * TWO LEVELS, AND THE DEPLOYMENT WINS. The deployment decides what exists at all
 * (`cbox-id.sign_in.*`, `cbox-id.sessions.*`); an environment's authentication policy
 * ({@see AuthPolicy}) may switch off a method the deployment offers, or shorten a session
 * below the deployment's maximum. It can never turn on what the deployment switched off,
 * nor lengthen a session past the deployment's cap — the operator's configuration is a
 * ceiling, not a default.
 *
 * Every question is asked of the AMBIENT environment, like {@see AuthPolicies::forEnvironment()}
 * — so a queued job or a request with no environment gets the deployment's answer.
 *
 * Callers ask here rather than reading the policy and the configuration themselves, because
 * the combination has edge cases (an idle timeout of 0 means "none", an idle timeout may not
 * outlast the absolute one) that would otherwise be answered differently in every place
 * that needed them.
 */
interface SignInMethods
{
    /** Whether a person may sign in with — and add — a passkey here. */
    public function passkeysEnabled(): bool;

    /** Whether a one-time sign-in link may be emailed and redeemed here. */
    public function magicLinkEnabled(): bool;

    /** How long a new session may last at most, in minutes. Always at least 1. */
    public function sessionAbsoluteMinutes(): int;

    /** How long a session may sit unused before it ends, in minutes; 0 means no idle timeout. */
    public function sessionIdleMinutes(): int;

    /** Whether the deployment offers passkeys at all — the ceiling the environment sits under. */
    public function deploymentAllowsPasskeys(): bool;

    /** Whether the deployment offers magic links at all. */
    public function deploymentAllowsMagicLink(): bool;

    /** The deployment's absolute session cap, in minutes — the most an environment may choose. */
    public function deploymentSessionAbsoluteMinutes(): int;

    /** The deployment's idle timeout, in minutes; 0 when the deployment sets none. */
    public function deploymentSessionIdleMinutes(): int;
}

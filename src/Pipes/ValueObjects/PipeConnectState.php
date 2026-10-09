<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

/**
 * What a connect flow carries between the redirect to the provider and the callback, kept
 * by the HOST in the person's session (never in the URL):
 *
 *  - `state` binds the callback to the browser that started it (CSRF, RFC 6749 §10.12);
 *  - `codeVerifier` is the PKCE secret (RFC 7636) — only its hash went to the provider,
 *    so a code intercepted on the way back cannot be exchanged by anyone else;
 *  - `pipeId` and `userId` pin the result to the pipe and the person who STARTED the
 *    flow, so a callback cannot attach an account to somebody who did not ask for it;
 *  - `redirectUri` must be repeated exactly at the token endpoint.
 *
 * A value object rather than an array, because every reader of a session value would
 * otherwise re-check its shape for itself — see FederationFlowState for what happened
 * when one forgot.
 */
readonly class PipeConnectState
{
    public function __construct(
        public string $state,
        public string $codeVerifier,
        public string $pipeId,
        public string $userId,
        public string $redirectUri,
    ) {}

    /** Parse whatever came out of a session — `mixed`, and not to be trusted about shape. */
    public static function fromMixed(mixed $value): ?self
    {
        if (! is_array($value)) {
            return null;
        }

        $fields = [];

        foreach (['state', 'code_verifier', 'pipe_id', 'user_id', 'redirect_uri'] as $key) {
            $field = $value[$key] ?? null;

            if (! is_string($field) || $field === '') {
                return null;
            }

            $fields[$key] = $field;
        }

        return new self($fields['state'], $fields['code_verifier'], $fields['pipe_id'], $fields['user_id'], $fields['redirect_uri']);
    }

    /**
     * @return array{state: string, code_verifier: string, pipe_id: string, user_id: string, redirect_uri: string}
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'code_verifier' => $this->codeVerifier,
            'pipe_id' => $this->pipeId,
            'user_id' => $this->userId,
            'redirect_uri' => $this->redirectUri,
        ];
    }

    /** Constant-time, because this is the CSRF comparison. */
    public function matches(string $state): bool
    {
        return $state !== '' && hash_equals($this->state, $state);
    }
}

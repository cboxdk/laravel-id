<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use Cbox\Id\SamlIdp\ValueObjects\SamlError;
use RuntimeException;

/**
 * Thrown when an inbound SAML `AuthnRequest` is rejected: malformed XML (or a
 * DOCTYPE/XXE payload), a missing issuer or id, an AssertionConsumerServiceURL
 * that does not match the registered ACS, a required-but-absent signature, an
 * unknown signature algorithm, a signature that fails to verify, a wrong or
 * absent `Destination`, a stale or replayed request, or a `NameIDPolicy` the
 * registered SP cannot be answered under. Never carries the raw request payload.
 *
 * Some of those refusals can be reported to the SP in its own language — a SAML
 * `Response` with a failure `StatusCode` — rather than as an opaque HTTP error.
 * Those carry a {@see SamlError}; see that class for why only refusals that have
 * already cleared the trust gates may do so.
 */
class InvalidAuthnRequest extends RuntimeException
{
    private ?SamlError $samlError = null;

    public static function make(string $reason): self
    {
        return new self('invalid AuthnRequest: '.$reason);
    }

    /**
     * A refusal the SP can be told about in SAML. The reason is repeated into the
     * response's `StatusMessage`, so keep it free of request internals.
     */
    public static function reportable(string $reason, SamlError $error): self
    {
        $exception = self::make($reason);
        $exception->samlError = $error;

        return $exception;
    }

    /** The SAML error to deliver to the SP's ACS, or null when there is none. */
    public function samlError(): ?SamlError
    {
        return $this->samlError;
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use InvalidArgumentException;

/**
 * Thrown when a requested environment custom domain is refused: a malformed
 * hostname, a bare IP, a domain reserved by the platform (a configured base
 * domain or its subdomains), or one already claimed by another environment.
 * Deny-by-default — the IdP never advertises an issuer host it has not validated.
 */
class InvalidCustomDomain extends InvalidArgumentException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function malformed(string $domain): self
    {
        return (new self('not a valid domain name: '.$domain))->withSourceMessage(new SourceMessage('not a valid domain name: :domain', ['domain' => $domain]));
    }

    public static function reserved(string $domain): self
    {
        return (new self('this domain is managed by the platform and cannot be used as a custom domain: '.$domain))->withSourceMessage(new SourceMessage('this domain is managed by the platform and cannot be used as a custom domain: :domain', ['domain' => $domain]));
    }

    public static function taken(string $domain): self
    {
        return (new self('this domain is already in use by another environment: '.$domain))->withSourceMessage(new SourceMessage('this domain is already in use by another environment: :domain', ['domain' => $domain]));
    }
}

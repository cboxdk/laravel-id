<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

/**
 * A signed SAML 2.0 Response ready to deliver to the SP over the HTTP-POST
 * binding. `xml` is the raw signed document; `encoded` is its base64 form (the
 * `SAMLResponse` form field); `acsUrl` is the registered ACS it must be POSTed to;
 * `relayState` is echoed back untouched.
 */
final readonly class SamlResponse
{
    public function __construct(
        public string $xml,
        public string $encoded,
        public string $acsUrl,
        public ?string $relayState = null,
    ) {}

    /**
     * Render the self-submitting HTML form that carries the response to the SP's
     * ACS (SAML bindings §3.5, HTTP-POST). Every interpolated value is escaped —
     * `relayState` in particular is attacker-influenced and must never break out of
     * the attribute context.
     */
    public function toPostForm(string $title = 'Redirecting…'): string
    {
        $action = htmlspecialchars($this->acsUrl, ENT_QUOTES, 'UTF-8');
        $response = htmlspecialchars($this->encoded, ENT_QUOTES, 'UTF-8');
        $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');

        $relay = '';
        if ($this->relayState !== null && $this->relayState !== '') {
            $value = htmlspecialchars($this->relayState, ENT_QUOTES, 'UTF-8');
            $relay = '<input type="hidden" name="RelayState" value="'.$value.'"/>';
        }

        return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>'.$safeTitle.'</title></head>'
            .'<body onload="document.forms[0].submit()">'
            .'<noscript><p>Your browser does not support JavaScript. Continue to complete sign-in.</p></noscript>'
            .'<form method="post" action="'.$action.'">'
            .'<input type="hidden" name="SAMLResponse" value="'.$response.'"/>'
            .$relay
            .'<noscript><input type="submit" value="Continue"/></noscript>'
            .'</form></body></html>';
    }
}

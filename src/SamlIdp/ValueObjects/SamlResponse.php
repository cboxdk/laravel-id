<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

/**
 * A signed SAML 2.0 Response ready to deliver to the SP over the HTTP-POST
 * binding. `xml` is the raw signed document; `encoded` is its base64 form (the
 * `SAMLResponse` form field); `acsUrl` is the registered ACS it must be POSTed to;
 * `relayState` is echoed back untouched.
 */
readonly class SamlResponse
{
    public function __construct(
        public string $xml,
        public string $encoded,
        public string $acsUrl,
        public ?string $relayState = null,
    ) {}

    /**
     * The self-submitting form together with the policy that permits it.
     *
     * Prefer this over {@see toPostForm()} in any host that sets a Content-Security-
     * Policy, which should be every host: a policy strict enough to be worth having
     * blocks this page twice over, once on `form-action` and once on the inline
     * submit. See {@see SamlPostBinding} for what the emitted policy allows and why
     * it cannot be widened by anything the request carries.
     */
    public function toPostBinding(string $title = 'Redirecting…'): SamlPostBinding
    {
        // 128 bits, per-response. A nonce reused across responses is a nonce an
        // attacker can pre-load a script against.
        $nonce = base64_encode(random_bytes(16));

        return new SamlPostBinding(
            html: $this->toPostForm($title, $nonce),
            contentSecurityPolicy: implode('; ', [
                "default-src 'none'",
                "script-src 'nonce-".$nonce."'",
                // The one origin this assertion is addressed to. Taken from the
                // registration, never from the request — an SP cannot name someone
                // else's ACS and have the policy allow it.
                'form-action '.self::originOf($this->acsUrl),
                "base-uri 'none'",
                "frame-ancestors 'none'",
            ]),
        );
    }

    /**
     * Render the self-submitting HTML form that carries the response to the SP's
     * ACS (SAML bindings §3.5, HTTP-POST). Every interpolated value is escaped —
     * `relayState` in particular is attacker-influenced and must never break out of
     * the attribute context.
     *
     * The submit runs from a `<script>` rather than a `body onload` handler so that a
     * host applying a policy has something to permit: an event-handler attribute can
     * only be allowed by `'unsafe-inline'`, which is all-or-nothing for the whole
     * page, while a nonce'd script permits exactly this one. Without a nonce the tag
     * still runs — a browser ignores the attribute when no policy names it — so a
     * host with no CSP is unaffected.
     */
    public function toPostForm(string $title = 'Redirecting…', ?string $nonce = null): string
    {
        $action = htmlspecialchars($this->acsUrl, ENT_QUOTES, 'UTF-8');
        $response = htmlspecialchars($this->encoded, ENT_QUOTES, 'UTF-8');
        $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');

        $relay = '';
        if ($this->relayState !== null && $this->relayState !== '') {
            $value = htmlspecialchars($this->relayState, ENT_QUOTES, 'UTF-8');
            $relay = '<input type="hidden" name="RelayState" value="'.$value.'"/>';
        }

        $nonceAttribute = $nonce !== null
            ? ' nonce="'.htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8').'"'
            : '';

        return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>'.$safeTitle.'</title></head>'
            .'<body>'
            .'<noscript><p>Your browser does not support JavaScript. Continue to complete sign-in.</p></noscript>'
            .'<form method="post" action="'.$action.'">'
            .'<input type="hidden" name="SAMLResponse" value="'.$response.'"/>'
            .$relay
            .'<noscript><input type="submit" value="Continue"/></noscript>'
            .'</form>'
            .'<script'.$nonceAttribute.'>document.forms[0].submit();</script>'
            .'</body></html>';
    }

    /**
     * The scheme, host and port of a URL — a CSP source, not a path.
     *
     * `form-action` matches on origin and path prefix, and naming the full ACS path
     * would break the moment a service provider appends a query string to its own
     * endpoint. The origin is the security boundary that matters: it says this
     * assertion may be posted to that host and nowhere else.
     */
    private static function originOf(string $url): string
    {
        $parts = parse_url($url);

        $scheme = is_string($parts['scheme'] ?? null) ? $parts['scheme'] : null;
        $host = is_string($parts['host'] ?? null) ? $parts['host'] : null;

        if ($scheme === null || $host === null) {
            // Unparseable — refuse rather than echo. Returning the raw string put an
            // unvalidated value straight into a response header: an ACS containing a
            // semicolon would inject its own directives BEFORE `base-uri` and
            // `frame-ancestors`, and first occurrence wins, so a malformed registration
            // could weaken the two directives that keep this page out of a frame.
            //
            // `'none'` breaks that one delivery, loudly, for one service provider whose
            // registration is already wrong. The alternative is a policy that quietly
            // means less than it says, which is discovered by whoever it happens to.
            return "'none'";
        }

        $port = $parts['port'] ?? null;

        return $scheme.'://'.$host.(is_int($port) ? ':'.$port : '');
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Saml;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\SamlSpSingleLogout;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\SamlIdp\Support\MessageGuard;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Utils;
use Throwable;

/**
 * SAML 2.0 Single Logout (SLO), IdP-initiated: the IdP sends a signed
 * `LogoutRequest` to this SP's SLO endpoint (HTTP-Redirect binding); we verify it
 * with onelogin (signature + strict mode), terminate every local session for the
 * logged-out subject, and hand back the `LogoutResponse` redirect URL for the
 * browser to carry to the IdP.
 *
 * Signature verification is delegated to onelogin's {@see Auth::processSLO()} —
 * the part that is dangerous to hand-roll. onelogin reads the message and the
 * self-URL from PHP superglobals, so we pin those to the connection's SLO URL and
 * the actual query parameters for the duration of the call, exactly as the ACS
 * validator pins the request URL.
 */
class SamlLogout implements SamlSpSingleLogout
{
    /**
     * Both bounds a signature does not give you: freshness and single use. The
     * identity-provider half of this package has enforced them since it was written;
     * this half enforced neither, which made any captured LogoutRequest a permanent
     * logout primitive against the person it named.
     */
    private const FRESHNESS_SECONDS = 300;

    public function __construct(
        private readonly Connections $connections,
        private readonly SessionManager $sessions,
        private readonly MessageGuard $guard,
    ) {}

    /**
     * Result of processing an inbound SLO message.
     *
     * @param  array<string, string>  $query  the request query/body parameters (SAMLRequest|SAMLResponse, RelayState, SigAlg, Signature)
     */
    public function handle(Connection $connection, array $query): SamlLogoutResult
    {
        $config = $this->connections->samlConfig($connection);
        $sloUrl = $config->slsUrl();

        if ($sloUrl === null) {
            return SamlLogoutResult::error('This connection has no Single Logout endpoint configured.');
        }

        // SLO messages must be signed — the LogoutRequest itself is the security
        // boundary, so an unsigned one is rejected (no forced-logout by anyone).
        $settings = SamlSettings::toArray($config, requireSignedMessages: true);

        return $this->withPinnedGlobals($sloUrl, $query, function () use ($settings, $connection, $query): SamlLogoutResult {
            $auth = new Auth($settings);

            $revoked = 0;
            $redirect = null;
            try {
                // $stay=true → return the redirect URL instead of emitting headers.
                // keepLocalSession=true → we revoke platform sessions ourselves,
                // keyed by the LogoutRequest's NameID, not onelogin's PHP session.
                $redirect = $auth->processSLO(true, null, false, null, true);
            } catch (Throwable $e) {
                return SamlLogoutResult::error('SLO message could not be processed: '.$e->getMessage());
            }

            $errors = $auth->getErrors();
            if ($errors !== []) {
                return SamlLogoutResult::error('SLO signature or format invalid: '.implode(', ', array_filter($errors, 'is_string')));
            }

            // On an inbound LogoutRequest, revoke every session for that subject.
            if (isset($query['SAMLRequest'])) {
                // Signed is not the same as fresh, and not the same as unused.
                //
                // A LogoutRequest travels to us as a query string in the user's browser:
                // it lands in history, in proxy logs, in a Referer. The identity-provider
                // half of this package has enforced both bounds since it was written; the
                // relying-party half enforced neither, so anyone who obtained a copy held
                // a permanent, unauthenticated, targeted logout against one named person
                // — replayable on every re-login, forever. onelogin checks NotOnOrAfter
                // only when the message carries one, and most identity providers do not
                // send one on a LogoutRequest.
                //
                // Scoped to the CONNECTION rather than the IdP EntityID: two tenants may
                // federate to the same identity provider, and a replay key they share is
                // one tenant able to burn the other's message ids.
                if (! $this->guard->fresh($this->issueInstantOf($query['SAMLRequest']), self::FRESHNESS_SECONDS)) {
                    return SamlLogoutResult::error('The LogoutRequest is stale or its IssueInstant is unparseable.');
                }

                $messageId = $this->messageIdOf($query['SAMLRequest']);

                if ($messageId === null || ! $this->guard->consume($connection->id, $messageId, self::FRESHNESS_SECONDS)) {
                    return SamlLogoutResult::error('The LogoutRequest has already been processed (replay).');
                }

                $revoked = $this->revokeSessionsForRequest($connection, $query['SAMLRequest']);
            }

            return SamlLogoutResult::ok($redirect !== '' ? $redirect : null, $revoked);
        });
    }

    /**
     * `IssueInstant` off the root element, read from the raw payload.
     *
     * Attribute-scraped rather than DOM-parsed on purpose: this runs BEFORE the
     * decision to trust anything, so it must not hand attacker-supplied XML to a
     * parser. The value only ever feeds a freshness comparison — a wrong one fails
     * closed.
     */
    private function issueInstantOf(string $samlRequest): ?string
    {
        return preg_match('/IssueInstant="([^"]+)"/', $this->inflate($samlRequest), $matches) === 1
            ? $matches[1]
            : null;
    }

    /** The message `ID`, which is what makes the replay key unique. */
    private function messageIdOf(string $samlRequest): ?string
    {
        return preg_match('/\sID="([^"]+)"/', $this->inflate($samlRequest), $matches) === 1
            ? $matches[1]
            : null;
    }

    /** Inflate the payload to XML, tolerating an already-decoded (POST-binding) value. */
    private function inflate(string $samlRequest): string
    {
        $decoded = base64_decode($samlRequest, true);

        return is_string($decoded) ? (@gzinflate($decoded) ?: $decoded) : $samlRequest;
    }

    /**
     * Resolve the LogoutRequest's NameID to a local user and revoke all their
     * sessions. Returns the number of users whose sessions were revoked (0 or 1).
     */
    private function revokeSessionsForRequest(Connection $connection, string $samlRequest): int
    {
        // The redirect binding deflates the request; getNameId() wants the plain
        // XML. Inflate, falling back to a non-deflated (POST-binding) payload.
        $decoded = base64_decode($samlRequest, true);
        $xml = is_string($decoded) ? (@gzinflate($decoded) ?: $decoded) : $samlRequest;

        try {
            $nameId = LogoutRequest::getNameId($xml);
        } catch (Throwable) {
            return 0;
        }

        if ($nameId === '') {
            return 0;
        }

        // Scope the lookup to THIS connection, exactly as login does
        // (DatabaseSubjects::linkQuery matches connection_id). Without it, a
        // signature-valid LogoutRequest from connection A's IdP could revoke a
        // user belonging to connection B in the same environment when the two
        // IdPs happen to use the same NameID string.
        $userId = IdentityLink::query()
            ->where('provider', $connection->type->value)
            ->where('connection_id', $connection->id)
            ->where('subject', $nameId)
            ->value('user_id');

        if (! is_string($userId)) {
            return 0;
        }

        $this->sessions->revokeAllForUser($userId);

        return 1;
    }

    /**
     * Pin the superglobals onelogin reads (self-URL + inbound message params) for
     * the duration of $callback, then restore them.
     *
     * @param  array<string, string>  $query
     * @param  callable(): SamlLogoutResult  $callback
     */
    private function withPinnedGlobals(string $sloUrl, array $query, callable $callback): SamlLogoutResult
    {
        $parts = parse_url($sloUrl);
        $parts = is_array($parts) ? $parts : [];

        $host = is_string($parts['host'] ?? null) ? $parts['host'] : 'localhost';
        $scheme = ($parts['scheme'] ?? null) === 'http' ? 'http' : 'https';
        $path = is_string($parts['path'] ?? null) ? $parts['path'] : '/';
        if (isset($parts['port'])) {
            $host .= ':'.$parts['port'];
        }

        $savedServer = [];
        foreach (['HTTP_HOST', 'HTTPS', 'SCRIPT_NAME', 'REQUEST_URI', 'PATH_INFO', 'SERVER_PORT'] as $key) {
            $savedServer[$key] = $_SERVER[$key] ?? null;
        }
        $savedGet = $_GET;

        Utils::setBaseURL('');
        $_SERVER['HTTP_HOST'] = $host;
        $_SERVER['HTTPS'] = $scheme === 'https' ? 'on' : 'off';
        $_SERVER['SCRIPT_NAME'] = $path;
        $_SERVER['REQUEST_URI'] = $path;
        unset($_SERVER['PATH_INFO'], $_SERVER['SERVER_PORT']);
        $_GET = $query;

        try {
            return $callback();
        } finally {
            foreach ($savedServer as $key => $value) {
                if ($value === null) {
                    unset($_SERVER[$key]);
                } else {
                    $_SERVER[$key] = $value;
                }
            }
            $_GET = $savedGet;
        }
    }
}

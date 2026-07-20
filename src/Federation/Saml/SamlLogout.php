<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Saml;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Models\IdentityLink;
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
class SamlLogout
{
    public function __construct(
        private readonly Connections $connections,
        private readonly SessionManager $sessions,
    ) {}

    /**
     * Result of processing an inbound SLO message.
     *
     * @param  array<string, string>  $query  the request query/body parameters (SAMLRequest|SAMLResponse, RelayState, SigAlg, Signature)
     */
    public function handle(Connection $connection, array $query): SamlLogoutResult
    {
        $config = $this->connections->config($connection);
        $sloUrl = SamlSettings::slsUrl($config);

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
                $revoked = $this->revokeSessionsForRequest($connection, $query['SAMLRequest']);
            }

            return SamlLogoutResult::ok($redirect !== '' ? $redirect : null, $revoked);
        });
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

<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\RelyingParties;
use Cbox\Id\Identity\ValueObjects\RelyingParty;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;

/**
 * The Relying Party of the environment this request is on, derived from the one thing
 * that already names an environment's host: its issuer.
 *
 * `rp_id` and `origin` used to be a single deployment-wide pair bound from static config
 * at register time. On any deployment with more than one host that is not a
 * misconfiguration you can fix — it is unsatisfiable. With the pair set to the account
 * root, every tenant subdomain's browser reported a different origin and every tenant
 * passkey was rejected with "origin mismatch"; set to a tenant, the account plane broke
 * instead. A verified custom domain failed twice over, since the root's registrable
 * domain is not a suffix of `id.acme.com` either.
 *
 * The RP id is the environment's FULL host, not the base domain it sits under. A passkey
 * enrolled at `acme.cboxid.com` is that tenant's credential; scoping it to `cboxid.com`
 * would offer it to every other tenant's sign-in page on the same base domain, which is
 * the isolation boundary this platform is built around.
 */
class EnvironmentRelyingParties implements RelyingParties
{
    public function __construct(private readonly IssuerResolver $issuers) {}

    public function current(): RelyingParty
    {
        $pinned = $this->pinned();

        // A pin is a DEPLOYMENT-WIDE answer, so it holds exactly where the environment
        // takes the deployment-wide ISSUER too: the platform root, single-tenant, on-prem,
        // and the reverse-proxy case the config key exists for. That is what
        // `canonicalHost() === null` means.
        //
        // An environment that owns a host has already contradicted the pin — the browser
        // there reports that host's origin — so honouring it would not enforce the
        // operator's intent, only guarantee a rejected ceremony. It matters that the pin
        // loses HERE rather than being written differently: the installer writes the pair
        // on every install, so a pin that always won would leave this fix inert on
        // precisely the deployments that already have one. `cbox-id:doctor` reports which
        // answer is in force.
        return $pinned !== null && $this->issuers->canonicalHost() === null
            ? $pinned
            : $this->derived();
    }

    /**
     * The pinned pair, or null unless BOTH keys are set. Half a pin is not a pin: an
     * rp_id without its origin (or the reverse) is exactly the jointly-impossible pair
     * {@see RelyingParty} exists to keep from being assembled.
     */
    public function pinned(): ?RelyingParty
    {
        $rpId = config('cbox-id.webauthn.rp_id');
        $origin = config('cbox-id.webauthn.origin');

        return is_string($rpId) && $rpId !== '' && is_string($origin) && $origin !== ''
            ? new RelyingParty($rpId, rtrim($origin, '/'))
            : null;
    }

    /**
     * The environment's own party. The issuer is already the canonical `scheme://host`
     * of this environment — the same value discovery publishes and tokens are minted
     * with — so the origin a browser on it reports is that string, and the RP id is its
     * host. Rebuilt from the parsed parts rather than used raw, so a configured issuer
     * carrying a path can never end up asserted as an origin.
     */
    public function derived(): RelyingParty
    {
        $issuer = $this->issuers->issuer();

        $host = parse_url($issuer, PHP_URL_HOST);
        $host = is_string($host) && $host !== '' ? $host : 'localhost';

        $scheme = parse_url($issuer, PHP_URL_SCHEME);
        $scheme = is_string($scheme) && $scheme !== '' ? $scheme : 'https';

        $port = parse_url($issuer, PHP_URL_PORT);

        return new RelyingParty($host, $scheme.'://'.$host.(is_int($port) ? ':'.$port : ''));
    }
}

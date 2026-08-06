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
        if ($pinned === null) {
            return $this->derived();
        }

        if ($this->issuers->canonicalHost() === null) {
            return $pinned;
        }

        // …and it ALSO holds where it is still a valid answer for the host in front of us.
        //
        // WebAuthn allows an RP id to be the origin's host OR a registrable suffix of it,
        // and `docs/configuration/environment-variables.md` tells operators to pin "usually
        // the registrable domain". So an on-prem deployment that followed our own advice —
        // `rp_id=acme.com`, the one environment serving `id.acme.com` — has a pin that is
        // correct, in force, and has credentials enrolled against it.
        //
        // Overriding it would move the id to `id.acme.com`, and an authenticator is never
        // even OFFERED a credential scoped to a different id: every passkey holder on that
        // deployment is locked out silently, with no error to read and no way back, because
        // no credential stores the id it was enrolled under.
        //
        // A suffix cannot simply always win, though. In the subdomain SaaS shape, honouring
        // `cboxid.com` on `acme.cboxid.com` offers one tenant's passkey on another tenant's
        // sign-in page. So the question is not "is the pin a suffix" but "is this host a
        // TENANT host" — a label under a configured base domain. On one, the pin loses and
        // nothing is stranded, because a tenant passkey could never have enrolled there in
        // the first place: registration compared the browser's origin against the single
        // pinned one and always failed. That is the bug this whole change exists to fix.
        return $this->pinCoversHost($pinned) ? $pinned : $this->derived();
    }

    /**
     * Whether the pinned party is a valid — and safe — answer for the environment's host.
     *
     * Valid: the host is the pinned id, or a subdomain of it (WebAuthn's registrable-suffix
     * rule). Safe: the host is not a tenant label under a configured base domain, where a
     * shared id would span tenants.
     */
    private function pinCoversHost(RelyingParty $pinned): bool
    {
        $host = $this->issuers->canonicalHost();

        if ($host === null || $this->isTenantHost($host)) {
            return false;
        }

        // BOTH halves. The id is what an authenticator scopes a credential to; the ORIGIN
        // is what `NativeWebAuthnVerifier` compares byte-for-byte against the browser's
        // clientDataJSON. A pin whose id covers the host but whose origin does not is the
        // jointly-impossible pair `RelyingParty`'s own docblock warns about, and it is what
        // an operator produces by following "usually the registrable domain" for BOTH keys:
        // `rp_id=acme.com`, `origin=https://acme.com`, on an environment serving
        // `id.acme.com`. Validating the id alone let that pin win, and then every
        // registration and every assertion failed with "origin mismatch".
        //
        // A pin whose origin names a different host is not a preference this deployment can
        // honour — it is a statement about a host that is not the one answering — so it
        // loses to the derived pair rather than guaranteeing a rejected ceremony.
        if ($pinned->host() !== $host) {
            return false;
        }

        return $host === $pinned->id || str_ends_with($host, '.'.$pinned->id);
    }

    /** Whether this host is a label under one of the deployment's tenant base domains. */
    private function isTenantHost(string $host): bool
    {
        $bases = config('cbox-id.environments.base_domains', []);

        if (! is_array($bases)) {
            return false;
        }

        foreach ($bases as $base) {
            if (is_string($base) && $base !== '' && str_ends_with($host, '.'.mb_strtolower(ltrim(trim($base), '.')))) {
                return true;
            }
        }

        return false;
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

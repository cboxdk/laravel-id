<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Testing;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\DnsResolver;
use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\VerifiedDomain;
use Cbox\Id\Federation\Support\FederationFlowStash;
use Cbox\Id\Federation\ValueObjects\FederationFlowState;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use LogicException;
use Symfony\Component\HttpFoundation\Cookie as BrowserCookie;

trait InteractsWithFederation
{
    /** Begin a real browser-bound flow when a test drives the callback directly. */
    protected function stashFederationFlow(string $connectionId, FederationFlowState $flow): BrowserCookie
    {
        $session = app(Session::class);
        $session->start();
        $request = Request::create('/');
        $request->setLaravelSession($session);
        app(FederationFlowStash::class)->put($request, $connectionId, $flow);

        return Cookie::queued('__Host-cbox_fed_'.preg_replace('/[^A-Za-z0-9]/', '', $connectionId))
            ?? throw new LogicException('The federation flow did not issue its browser cookie.');
    }

    /**
     * @param  array<string, mixed>  $config
     */
    protected function makeConnection(
        string $organizationId,
        ConnectionType $type = ConnectionType::Saml,
        string $name = 'Okta',
        array $config = [],
        bool $active = true,
        ?string $provider = null,
    ): Connection {
        $connections = app(Connections::class);
        $connection = $connections->create($organizationId, $type, $name, $config, provider: $provider);

        if ($active) {
            $connections->activate($organizationId, $connection->id);
        }

        return $connection->refresh();
    }

    /**
     * Swap the DNS resolver for an in-memory fake and return it, so a test can
     * publish TXT records before verifying a domain.
     */
    protected function fakeDns(): FakeDnsResolver
    {
        // Resolved through the PSR-11 accessor, not `app(DnsResolver::class)`: the
        // helper's return type is inferred from the container BINDING, so static
        // analysis concludes the concrete SystemDnsResolver is the only possible
        // result and that the check below is dead. Rebinding the contract is exactly
        // what this method does, so that inference is wrong about runtime — `get()`
        // returns mixed and lets the instanceof mean what it says.
        $current = app()->get(DnsResolver::class);

        if ($current instanceof FakeDnsResolver) {
            return $current;
        }

        $fake = new FakeDnsResolver;
        app()->instance(DnsResolver::class, $fake);
        // The DomainVerification singleton was built with the real resolver;
        // forget it so the next resolve rebuilds it against the fake.
        app()->forgetInstance(DomainVerification::class);

        return $fake;
    }

    /**
     * Register a domain and, by default, verify it by publishing the challenge to
     * the fake resolver — the common "org already proved this domain" setup.
     */
    protected function makeVerifiedDomain(string $organizationId, string $domain, bool $verified = true): VerifiedDomain
    {
        // Fake DNS BEFORE resolving the service, so the resolver it is built with
        // is the fake (the service is a singleton captured at first resolve).
        $dns = $verified ? $this->fakeDns() : null;
        $domains = app(DomainVerification::class);
        $record = $domains->add($organizationId, $domain);

        if ($dns !== null) {
            $dns->publish($domains->challengeHost($domain), $record->verification_token);
            $domains->verify($record->id);
        }

        return $record->refresh();
    }
}

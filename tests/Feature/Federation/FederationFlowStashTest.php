<?php

declare(strict_types=1);

use Cbox\Id\Federation\Support\FederationFlowStash;
use Cbox\Id\Federation\ValueObjects\FederationFlowState;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cookie;

function flowStashRequest(array $cookies = []): Request
{
    $request = Request::create('https://id.example.test/callback', 'POST', cookies: $cookies);
    $request->setLaravelSession(new Store('flow-test', new ArraySessionHandler(120)));

    return $request;
}

it('sets and clears a host-only cookie even when the cookie jar has a parent domain', function (): void {
    Cookie::setDefaultPathAndDomain('/', '.example.test');
    $stash = app(FederationFlowStash::class);
    $request = flowStashRequest();
    $stash->put($request, 'connection', FederationFlowState::fresh());
    $issued = Cookie::queued('__Host-cbox_fed_connection');

    expect($issued)->not->toBeNull()
        ->and($issued->getDomain())->toBeNull()
        ->and($issued->getPath())->toBe('/')
        ->and($issued->isSecure())->toBeTrue()
        ->and($issued->isHttpOnly())->toBeTrue()
        ->and($issued->getSameSite())->toBe('none');

    $stash->pull(flowStashRequest([$issued->getName() => $issued->getValue()]), 'connection');
    $deleted = Cookie::queued($issued->getName());
    expect($deleted->getDomain())->toBeNull()
        ->and($deleted->getPath())->toBe('/')
        ->and($deleted->isSecure())->toBeTrue()
        ->and($deleted->getExpiresTime())->toBeLessThan(time());
});

it('expires the flow server-side even if the browser keeps the cookie', function (): void {
    $stash = app(FederationFlowStash::class);
    $stash->put(flowStashRequest(), 'connection', FederationFlowState::fresh());
    $cookie = Cookie::queued('__Host-cbox_fed_connection');
    $this->travel(10)->minutes();

    expect($stash->pull(flowStashRequest([$cookie->getName() => $cookie->getValue()]), 'connection'))->toBeNull();
});

it('consumes a flow only once even if its cookie is sent again', function (): void {
    $stash = app(FederationFlowStash::class);
    $flow = FederationFlowState::fresh();
    $stash->put(flowStashRequest(), 'connection', $flow);
    $cookie = Cookie::queued('__Host-cbox_fed_connection');
    $cookies = [$cookie->getName() => $cookie->getValue()];

    expect($stash->pull(flowStashRequest($cookies), 'connection'))->toEqual($flow)
        ->and($stash->pull(flowStashRequest($cookies), 'connection'))->toBeNull();
});

it('does not authorize a callback from a copied session or a legacy flow cookie', function (): void {
    $stash = app(FederationFlowStash::class);
    $flow = FederationFlowState::fresh();
    $initiator = flowStashRequest();
    $stash->put($initiator, 'connection', $flow);
    $cookie = Cookie::queued('__Host-cbox_fed_connection');
    $request = flowStashRequest(['cbox_fed_connection' => json_encode($flow->toArray())]);
    $request->session()->put('oidc.connection', $flow->toArray());

    expect($stash->pull($request, 'connection'))->toBeNull();

    // Even possessing the new opaque token in the session cannot substitute for
    // the __Host cookie, which a sibling domain is unable to install.
    $request->session()->put('oidc.connection', $cookie->getValue());
    expect($stash->pull($request, 'connection'))->toBeNull();
});

it('does not recover a flow using its public authorization state', function (): void {
    $stash = app(FederationFlowStash::class);
    $flow = FederationFlowState::fresh();
    $stash->put(flowStashRequest(), 'connection', $flow);

    expect($stash->pull(flowStashRequest(['__Host-cbox_fed_connection' => $flow->state]), 'connection'))->toBeNull();
});

it('binds the server-side flow to its connection', function (): void {
    $stash = app(FederationFlowStash::class);
    $stash->put(flowStashRequest(), 'first', FederationFlowState::fresh());
    $cookie = Cookie::queued('__Host-cbox_fed_first');

    expect($stash->pull(flowStashRequest(['__Host-cbox_fed_second' => $cookie->getValue()]), 'second'))->toBeNull();
});

it('allows only one callback when two requests read the pending flow concurrently', function (): void {
    $cache = new class(new ArrayStore) extends Repository
    {
        public function get($key, $default = null): mixed
        {
            $value = parent::get($key, $default);
            if (! str_ends_with((string) $key, ':used')) {
                Fiber::suspend();
            }

            return $value;
        }
    };
    $stash = new FederationFlowStash($cache);
    $flow = FederationFlowState::fresh();
    $stash->put(flowStashRequest(), 'connection', $flow);
    $cookie = Cookie::queued('__Host-cbox_fed_connection');
    $cookies = [$cookie->getName() => $cookie->getValue()];
    $first = new Fiber(fn () => $stash->pull(flowStashRequest($cookies), 'connection'));
    $second = new Fiber(fn () => $stash->pull(flowStashRequest($cookies), 'connection'));

    // Both reads finish before either callback can consume the flow.
    $first->start();
    $second->start();
    $first->resume();
    $second->resume();

    expect($first->getReturn())->toEqual($flow)
        ->and($second->getReturn())->toBeNull();
});

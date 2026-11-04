<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\ValueObjects\FederationFlowState;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Cookie as BrowserCookie;

/**
 * An opaque browser secret identifies a short-lived, single-use server-side flow.
 * The host-only cookie survives cross-site form_post callbacks, where a Lax session
 * cookie is absent. Neither the public state nor a sibling-domain cookie can recover
 * the flow. A session cookie alone is insufficient: it may itself be planted by a
 * sibling domain, so callbacks always require the protected flow cookie.
 */
class FederationFlowStash
{
    use ResolvesEnvironment;

    private const LIFETIME_SECONDS = 600;

    public function __construct(private readonly Cache $cache) {}

    public function put(Request $request, string $connectionId, FederationFlowState $flow): void
    {
        $token = bin2hex(random_bytes(32));
        $expiresAt = now()->getTimestamp() + self::LIFETIME_SECONDS;

        $this->cache->put($this->cacheKey($connectionId, $token), [
            'flow' => $flow->toArray(),
            'expires_at' => $expiresAt,
        ], self::LIFETIME_SECONDS);
        $request->session()->forget(self::sessionKey($connectionId));

        Cookie::queue(self::cookie($connectionId, $token, $expiresAt));
    }

    public function pull(Request $request, string $connectionId): ?FederationFlowState
    {
        $request->session()->forget(self::sessionKey($connectionId));
        $token = self::token($request->cookie(self::cookieName($connectionId)));

        Cookie::queue(self::cookie($connectionId, '', 1));

        if ($token === null) {
            return null;
        }

        $key = $this->cacheKey($connectionId, $token);
        $stored = $this->cache->get($key);
        if (! is_array($stored) || ! is_int($stored['expires_at'] ?? null)
            || $stored['expires_at'] <= now()->getTimestamp()) {
            return null;
        }

        $flow = FederationFlowState::fromMixed($stored['flow'] ?? null);
        if ($flow === null || ! $this->cache->add($key.':used', true, self::LIFETIME_SECONDS)) {
            return null;
        }

        // Cache::pull is a get followed by a delete, not an atomic claim. The marker
        // above arbitrates concurrent callbacks before either can exchange a code.
        $this->cache->forget($key);

        return $stored['expires_at'] > now()->getTimestamp() ? $flow : null;
    }

    private function cacheKey(string $connectionId, string $token): string
    {
        $environment = $this->environments()->current()?->environmentKey() ?? 'none';

        return 'cbox:oidc:flow:'.hash('sha256', $environment.':'.$connectionId.':'.$token);
    }

    private static function sessionKey(string $connectionId): string
    {
        return 'oidc.'.$connectionId;
    }

    private static function cookieName(string $connectionId): string
    {
        return '__Host-cbox_fed_'.preg_replace('/[^A-Za-z0-9]/', '', $connectionId);
    }

    private static function token(mixed $value): ?string
    {
        return is_string($value) && preg_match('/\A[a-f0-9]{64}\z/', $value) === 1 ? $value : null;
    }

    private static function cookie(string $connectionId, string $value, int $expiresAt): BrowserCookie
    {
        // CookieJar::make(domain: null) inherits session.domain. Construct directly
        // so both issuance and deletion always satisfy the __Host- browser rules.
        return new BrowserCookie(
            name: self::cookieName($connectionId),
            value: $value,
            expire: $expiresAt,
            path: '/',
            domain: null,
            secure: true,
            httpOnly: true,
            raw: false,
            sameSite: BrowserCookie::SAMESITE_NONE,
        );
    }
}

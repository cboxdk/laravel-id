<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Http\Controllers;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Dpop\DpopResourceGuard;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Who the browser is signed in as, shaped for a component to draw.
 *
 * WHY THIS EXISTS BESIDE `/oauth/userinfo`, which returns roughly the same facts: that
 * endpoint is a protocol surface with a protocol's constraints — it answers 401 to an
 * anonymous caller, it is not CORS-enabled, and its shape is fixed by OIDC. A component
 * rendering an avatar needs the opposite of all three: a cross-origin call, a plain
 * `{"user": null}` when nobody is signed in, and a shape that includes what a menu
 * actually draws.
 *
 * SIGNED OUT IS NOT AN ERROR. `<UserButton/>` renders on every page including the ones
 * nobody has signed in on, and forcing it to treat 401 as a state rather than a failure
 * is how "flash of signed-out UI" bugs are born. Null is the answer to a fair question.
 *
 * WHAT IT STILL DEMANDS OF THE TOKEN. Being friendlier than `/oauth/userinfo` about the
 * SHAPE of the answer is not licence to be laxer about who may have it: the token must be
 * audienced for this issuer, must carry `openid`, and must satisfy its own DPoP binding
 * if it has one. Those are the same three checks UserInfo makes, and the endpoint that
 * skips them is the endpoint an attacker uses.
 *
 * THE PUBLISHABLE KEY GRANTS NOTHING HERE. The bearer token is the entire authority; the
 * key only got the request through the door and told us which environment to look in. A
 * page holding a key and no token learns nothing about anybody — which is the property
 * that makes the key safe to publish.
 */
class SessionController
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly Subjects $subjects,
        private readonly DpopResourceGuard $dpop,
        private readonly IssuerResolver $issuers,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $token = $this->bearer($request);

        if ($token === null) {
            return $this->anonymous();
        }

        $introspected = $this->introspector->introspect($token);

        if (! $introspected->active || $introspected->subject === null) {
            return $this->anonymous();
        }

        // FROM HERE ON, A REFUSAL IS A 401 AND NOT `{"user": null}`. Anonymous is the
        // answer to "nobody is signed in"; the three checks below all mean "this token is
        // not for this door", and answering them with a signed-out shape would render a
        // rejected stolen token identically to a logged-out visitor — invisible to the
        // integrator debugging it, and invisible in the logs.

        // A token minted for someone else's API (RFC 8707 `resource`) is not an identity
        // token for this endpoint. Without this, a resource server holding a customer's
        // access token could turn it into that customer's name and email address by
        // replaying it here.
        if (! $introspected->isAudience($this->issuers->issuer())) {
            return $this->challenge('the access token was not issued for this endpoint');
        }

        // Same requirement UserInfo makes. `openid` is what makes a token an identity
        // token; a pure API token was never granted the right to name its holder.
        if (! $introspected->hasScope('openid')) {
            return $this->challenge('the access token lacks the openid scope');
        }

        // A sender-constrained (cnf.jkt) token requires a valid DPoP proof over this exact
        // request and token. This endpoint used to read the bearer straight off the header
        // and skip the check, on the argument that minting a proof for it burdens an SDK
        // whose job is to draw an avatar — which handed a thief the one endpoint where a
        // stolen DPoP token still worked, and turned it into an id, a name and an email
        // address. The burden is real but it falls only on clients that asked to be
        // sender-constrained; for an ordinary bearer token enforce() returns immediately.
        try {
            $this->dpop->enforce($request, $token, $introspected);
        } catch (InvalidDpopProof $e) {
            return $this->challenge($e->getMessage(), scheme: 'DPoP');
        }

        $user = $this->subjects->find($introspected->subject);

        if ($user === null) {
            // The token is live and its subject is gone — a deleted user with an
            // unexpired token. Anonymous rather than an error: the page's correct
            // behaviour is identical to being signed out, and a 500 here would surface a
            // race as a crash on somebody's marketing site.
            return $this->anonymous();
        }

        return new JsonResponse([
            'user' => [
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
                // Deliberately not the raw model. A component needs a label, an initial
                // and an id; everything else on a user record is either private or
                // somebody else's business, and a passthrough is how it leaks.
            ],
        ])->header('Cache-Control', 'no-store');
    }

    /**
     * The bearer token, or null.
     *
     * Read straight off `Authorization` rather than through the DPoP helper the protocol
     * endpoints use: a DPoP proof is bound to a method and URL and would have to be minted
     * for this endpoint specifically, which is a burden on an SDK whose job here is to
     * draw an avatar. A sender-constrained token still works — it is simply not the
     * constraint being checked at this door, and this door grants nothing but a name.
     */
    private function bearer(Request $request): ?string
    {
        $header = (string) $request->headers->get('Authorization', '');

        if (! str_starts_with($header, 'Bearer ')) {
            return null;
        }

        $token = substr($header, 7);

        return $token !== '' ? $token : null;
    }

    private function anonymous(): JsonResponse
    {
        return new JsonResponse(['user' => null])->header('Cache-Control', 'no-store');
    }

    private function challenge(string $description, string $scheme = 'Bearer'): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'invalid_token', 'error_description' => $description],
            401,
            ['WWW-Authenticate' => $scheme.' error="invalid_token"'],
        )->header('Cache-Control', 'no-store');
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Http\Controllers;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
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
}

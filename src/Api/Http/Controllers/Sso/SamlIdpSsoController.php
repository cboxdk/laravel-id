<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\UnknownServiceProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * The IdP SingleSignOnService endpoint. It parses and validates the inbound
 * AuthnRequest (deny-by-default: unknown SP, ACS mismatch, or bad/missing required
 * signature are refused here), then — exactly as the OAuth authorize endpoint
 * leaves authentication to the host — hands off to the host's login when there is
 * no authenticated subject. Once a subject is present it mints the signed Response
 * and returns the self-submitting POST form to the SP's ACS.
 *
 * A host that wants full control over attribute release can ignore this controller
 * and drive {@see SamlIdentityProvider::parseAuthnRequest()} /
 * {@see SamlIdentityProvider::issueResponse()} itself.
 */
class SamlIdpSsoController
{
    public function __construct(
        private readonly SamlIdentityProvider $idp,
        private readonly Subjects $subjects,
    ) {}

    public function __invoke(Request $request): Response|RedirectResponse
    {
        $samlRequest = $this->stringParam($request, 'SAMLRequest');
        if ($samlRequest === null) {
            return new Response('Missing SAMLRequest.', 400);
        }

        $relayState = $this->stringParam($request, 'RelayState');

        try {
            $authnRequest = $this->idp->parseAuthnRequest(
                $samlRequest,
                $relayState,
                $this->stringParam($request, 'Signature'),
                $this->stringParam($request, 'SigAlg'),
                $request->isMethod('get'),
                $this->rawQueryString($request),
            );
        } catch (UnknownServiceProvider) {
            return new Response('Unknown or inactive SAML service provider.', 403);
        } catch (InvalidAuthnRequest $exception) {
            // A refusal the SP can be told about in SAML goes back to its ACS as a
            // signed Response with a failure StatusCode — the SP logs it and shows
            // its own error page, instead of the user landing on an unbranded 400
            // the SP never hears about. Everything else stays an opaque refusal.
            $error = $exception->samlError();

            if ($error === null) {
                return new Response('SAML AuthnRequest rejected.', 400);
            }

            try {
                $errorResponse = $this->idp->issueErrorResponse($error);
            } catch (UnknownServiceProvider) {
                // The SP was disabled between parsing and answering — there is no
                // trusted ACS left to deliver to.
                return new Response('Unknown or inactive SAML service provider.', 403);
            }

            return $errorResponse->toPostBinding()->toResponse();
        }

        // The host owns "who is logged in": no subject → hand off to its login and
        // let it re-dispatch this exact request once the user is authenticated.
        $subjectId = $this->authenticatedSubjectId();
        if ($subjectId === null) {
            return $this->handoff($request);
        }

        // No `amr` from here, deliberately: this controller resolves the subject through
        // Laravel's generic guard, which knows an id and nothing about HOW they signed in.
        // The assertion therefore says "unspecified" — vague, and true. A host that tracks
        // authentication methods passes them; see the parameter on issueResponse().
        // AND THE ACCOUNT HAS TO STILL BE ONE. The id above comes from Laravel's generic
        // guard, which knows an id and nothing else — so a session that outlived the
        // account behind it, or a host guard holding an id this environment has no
        // account for, produced a SIGNED assertion anyway. Every service provider that
        // trusts this IdP would then have accepted a leaver.
        //
        // AccountInactive's own docblock has said this since it was written: revoking
        // existing sessions is not enough if the login paths do not also refuse. This is
        // a login path — it is the moment an identity is asserted to somebody else.
        if (! $this->subjects->isActive($subjectId)) {
            return new Response('That account can no longer sign in.', 403);
        }

        $response = $this->idp->issueResponse($authnRequest, $subjectId, $this->attributesFor($subjectId));

        // The binding carries its own policy: a self-submitting form aimed at another
        // origin is what `form-action` exists to refuse, so the response has to say
        // which origin THIS assertion is for rather than the host loosening its policy
        // for every page it serves.
        return $response->toPostBinding()->toResponse();
    }

    /**
     * The authenticated subject id from the host's guard, or null when nobody is
     * signed in.
     */
    private function authenticatedSubjectId(): ?string
    {
        $id = auth()->id();

        return is_string($id) || is_int($id) ? (string) $id : null;
    }

    /**
     * The subject's releasable attributes, keyed by the field names the SP's
     * `name_id_attribute` / `attribute_mappings` reference. The default surfaces
     * email and name; a host issuing richer attributes drives issueResponse itself.
     *
     * @return array<string, string>
     */
    private function attributesFor(string $subjectId): array
    {
        $subject = $this->subjects->find($subjectId);

        $attributes = [];
        if ($subject?->email !== null && $subject->email !== '') {
            $attributes['email'] = $subject->email;
        }
        if ($subject?->name !== null && $subject->name !== '') {
            $attributes['name'] = $subject->name;
        }

        return $attributes;
    }

    private function handoff(Request $request): Response|RedirectResponse
    {
        $loginUrl = config('cbox-id.saml_idp.login_url');

        if (! is_string($loginUrl) || $loginUrl === '') {
            return new Response('Authentication required to complete SAML single sign-on.', 401);
        }

        // Carry the SSO URL so the host can return the browser here to resume once
        // the subject is authenticated — built from the RAW query string, never
        // `fullUrl()`. `fullUrl()` goes through Symfony's `normalizeQueryString()`,
        // which re-parses, `ksort()`s and re-encodes with `PHP_QUERY_RFC3986`: the
        // transmitted octets are gone, and a redirect-binding signature covers
        // exactly those octets. SimpleSAMLphp (and every PHP-based SP) writes a
        // space in `RelayState` as `+`, which comes back as `%20` — a request that
        // verified on the way in would then fail on the way back, after the user has
        // already logged in.
        $separator = str_contains($loginUrl, '?') ? '&' : '?';
        $rawQuery = $this->rawQueryString($request);
        $resumeUrl = $request->url().($rawQuery !== null ? '?'.$rawQuery : '');

        return new RedirectResponse($loginUrl.$separator.http_build_query(['return_to' => $resumeUrl]));
    }

    private function stringParam(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The query string exactly as received, still percent-encoded. Read from the
     * request's own server bag rather than the `$_SERVER` superglobal, which is not
     * per-request under Octane/Swoole.
     */
    private function rawQueryString(Request $request): ?string
    {
        $query = $request->server->get('QUERY_STRING');

        return is_string($query) && $query !== '' ? $query : null;
    }
}

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
            );
        } catch (UnknownServiceProvider) {
            return new Response('Unknown or inactive SAML service provider.', 403);
        } catch (InvalidAuthnRequest) {
            return new Response('SAML AuthnRequest rejected.', 400);
        }

        // The host owns "who is logged in": no subject → hand off to its login and
        // let it re-dispatch this exact request once the user is authenticated.
        $subjectId = $this->authenticatedSubjectId();
        if ($subjectId === null) {
            return $this->handoff($request);
        }

        $response = $this->idp->issueResponse($authnRequest, $subjectId, $this->attributesFor($subjectId));

        return new Response($response->toPostForm(), 200, ['Content-Type' => 'text/html; charset=UTF-8']);
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

        // Carry the full SSO URL so the host can return the browser here to resume
        // once the subject is authenticated.
        $separator = str_contains($loginUrl, '?') ? '&' : '?';

        return new RedirectResponse($loginUrl.$separator.http_build_query(['return_to' => $request->fullUrl()]));
    }

    private function stringParam(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}

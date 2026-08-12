<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Sources;

use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Migration\Contracts\LegacyCredentialSource;
use Cbox\Id\Migration\Support\SafeLegacyLoginUrl;
use Illuminate\Http\Client\Factory as Http;
use Throwable;

/**
 * An endpoint the customer runs, which knows what we do not.
 *
 * For the cases a database bridge cannot reach: the old credentials live behind an API, or
 * in a mainframe, or in a SaaS with an authentication endpoint and no export. The customer
 * writes a small handler, we POST an email and a password to it, and it answers yes with a
 * user or no.
 *
 * DELIBERATELY NOT A SCRIPT SANDBOX. Auth0 solves this by running the customer's
 * JavaScript inside their own runtime, and that is a code-execution surface in the
 * authentication path — a place where a customer's bug becomes our incident. An HTTP hop
 * buys the same flexibility with the blast radius on the side that wrote the code.
 *
 * THE PASSWORD CROSSES THE NETWORK, which is the whole point and also the thing to be
 * careful about. So: the same signed, SSRF-pinned, redirect-refusing transport the
 * external-actions hooks use — one hardening story in this package rather than two — plus
 * an HTTPS requirement that is not negotiable here even though the hook transport allows
 * an operator to relax it. A hook leaks metadata; this would leak a live credential.
 */
class HttpCredentialSource implements LegacyCredentialSource
{
    public function __construct(
        private readonly Http $http,
        private readonly string $url,
        private readonly string $secret,
        private readonly int $timeoutMs = 3000,
    ) {}

    public function verify(string $email, string $password): ?ImportedUser
    {
        return $this->ask(['email' => $email, 'password' => $password], $email);
    }

    public function find(string $email): ?ImportedUser
    {
        // No password: the handler is being asked "do you know this address", which is
        // for tooling only. The contract forbids the login path from using it.
        return $this->ask(['email' => $email], $email);
    }

    /**
     * @param  array<string, string>  $payload
     */
    private function ask(array $payload, string $asked): ?ImportedUser
    {
        if (! str_starts_with($this->url, 'https://')) {
            // Refused rather than warned. A credential over plain http is readable by
            // everything on the path, and the failure mode of "we logged a warning and
            // sent it anyway" is that nobody reads the log until afterwards.
            return null;
        }

        try {
            $body = json_encode($payload, JSON_THROW_ON_ERROR);
            $timestamp = time();

            // PINNED BY DEFAULT, and relaxable deliberately. A legacy system is very often
            // on a private network — that is what makes it legacy — and the SSRF guard
            // refuses private ranges precisely because most outbound URLs come from user
            // input. This one does not: an operator configured it. So the guard stays on
            // unless somebody states otherwise, and the same switch the external-action
            // hooks use is the one to state it with, rather than a second concept.
            $response = $this->http
                ->withOptions(SafeLegacyLoginUrl::pinnedOptions($this->url))
                ->timeout($this->timeoutMs / 1000)
                ->withHeaders([
                    'X-Cbox-Timestamp' => (string) $timestamp,
                    // The same construction the hook transport signs with, so a customer
                    // who has already written a verifier for one can reuse it verbatim.
                    'X-Cbox-Signature' => 't='.$timestamp.',v1='.hash_hmac('sha256', $timestamp.'.'.$body, $this->secret),
                    'Content-Type' => 'application/json',
                ])
                ->withBody($body, 'application/json')
                ->post($this->url);
        } catch (Throwable) {
            // Unreachable, timed out, TLS refused. A refusal, never a "no such user" —
            // the caller turns both into the same answer, which is what fail-closed means
            // here. See the contract.
            return null;
        }

        if (! $response->successful()) {
            // Includes the handler's own way of saying no. A 401 and a 500 mean different
            // things to the customer and the same thing to us: this person does not sign
            // in right now.
            return null;
        }

        return $this->toImportedUser($response->json(), $asked);
    }

    private function toImportedUser(mixed $json, string $asked): ?ImportedUser
    {
        if (! is_array($json)) {
            return null;
        }

        $email = $json['email'] ?? null;

        if (! is_string($email) || $email === '') {
            // A handler that answers 200 with nothing usable has said no in an unhelpful
            // way. Treated as no rather than as an error, because the alternative is an
            // exception on a login path over somebody else's response shape.
            return null;
        }

        if (mb_strtolower(trim($email)) !== mb_strtolower(trim($asked))) {
            // THE HANDLER ANSWERS ABOUT THE ADDRESS IT WAS ASKED ABOUT, or it does not
            // answer. Without this, a handler with a loose lookup — a LIKE, a join that
            // drops a WHERE, an alias table — lets somebody who knows one old password
            // be migrated in as whichever identity that query happened to return. The
            // handler is the customer's code, and this is our side of that trust.
            return null;
        }

        $name = $json['name'] ?? null;
        $hash = $json['password_hash'] ?? null;

        return new ImportedUser(
            email: $email,
            name: is_string($name) ? $name : null,
            // OPTIONAL, and usually absent. A handler that can return the original hash
            // lets the person keep their password here verbatim; one that cannot has
            // still proved the credential, and the caller hashes what it was given. Both
            // are legitimate — the second is what an opaque API can offer.
            passwordHash: is_string($hash) && $hash !== '' ? $hash : null,
            emailVerified: ($json['email_verified'] ?? false) === true,
        );
    }
}

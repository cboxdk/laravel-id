<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * What a CIBA approval was FOR, carried onto the tokens it yields.
 *
 * A resource server that asked a person to approve one specific thing (a deployment plan,
 * a payment) must be able to tell, from the token alone, that this approval is the one it
 * asked for and not another approval the same client holds. CIBA Core leaves that binding
 * to the client; these two claims give it something to check:
 *
 * - `auth_req_id` — the client's own handle for the request. Raw, because by the time a
 *   token carries it the handle is spent: redemption is single-use, so knowing it grants
 *   nothing. The client stored it when it started the request and compares it.
 * - `binding_message` — exactly what the person saw beside Approve. A client that put a
 *   digest (or a prefix of one) in the message can check it was the one approved.
 *
 * Only a CIBA grant has one. A refresh does not carry it on: the refreshed token is not
 * the approval, and a resource server checking for one should see that.
 */
readonly class BackchannelBinding
{
    public function __construct(
        public string $authReqId,
        public ?string $bindingMessage = null,
    ) {}

    /**
     * The claims, for the access token and the ID Token alike.
     *
     * @return array{auth_req_id: string, binding_message?: string}
     */
    public function claims(): array
    {
        $claims = ['auth_req_id' => $this->authReqId];

        if ($this->bindingMessage !== null && $this->bindingMessage !== '') {
            $claims['binding_message'] = $this->bindingMessage;
        }

        return $claims;
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\Subject;

/**
 * Hands an account whose address nobody had confirmed to the person who just proved they
 * receive mail at that address.
 *
 * AN UNVERIFIED ACCOUNT IS NOBODY'S YET. Self-service signup creates a usable account for
 * whatever address is typed, and the address stays unconfirmed until the mailbox answers.
 * Until then, whatever is set on the account — its password, second factors, passkeys,
 * linked sign-ins, personal API tokens, app grants and sessions — was set by whoever typed
 * the address, who need not be the person who reads that mailbox.
 *
 * Some flows open only for someone holding a link that was mailed to the address: a
 * sign-in link, an emailed invitation. Such a flow has PROVEN the mailbox, and an account
 * found by that address belongs to the person who proved it. {@see claim()} withdraws
 * everything set on the account before the proof and marks the address verified, in one
 * transaction, and records `user.unverified_account_claimed` in the audit log.
 *
 * A VERIFIED ACCOUNT IS LEFT ALONE. Its credentials were added by someone who had already
 * proven the address, and a second proof is no reason to take them away.
 *
 * The package calls this from {@see MagicLink::redeem()} and from
 * `Invitations::accept()`. A host that has its own mailbox-proving flow (an invitation page
 * that sets a password, an emailed one-time code) calls it before it attaches anything to
 * the account or signs anyone in to it. A host with its own {@see Subjects} resolver binds
 * its own implementation, or extends the default, to clear the credentials its store keeps.
 *
 * NOT CALLED BY {@see EmailVerification::verify()}. A verification token is minted for one
 * account, at that account's request (its signup, or its own change of address), and in
 * the ordinary case the person who opens it is the person who just set the account's
 * password; withdrawing that password and signing them out would punish every honest
 * signup. Verification therefore confirms the address of the account as it stands. A host
 * that wants the stricter rule — verifying only while signed in to the account, or
 * claiming when the verifier is not — applies it in the controller that calls `verify()`.
 */
interface MailboxProof
{
    /**
     * Claim `$subject` for whoever just proved `$provenEmail`.
     *
     * A no-op, returning the subject as it stands, when the account is already verified or
     * when its address is not `$provenEmail` (compared case-insensitively): a proof of one
     * mailbox says nothing about an account under another. A caller can tell the outcomes
     * apart by the returned subject's `emailVerified`.
     *
     * @return Subject the account as it now stands
     */
    public function claim(Subject $subject, string $provenEmail): Subject;
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\ValueObjects;

use InvalidArgumentException;

/**
 * An app telling us where its old login lives — a PROPOSAL, never an instruction.
 *
 * The manifest is how an application already declares facts about itself: its roles, its
 * permissions, versioned with its deploy so nothing drifts from what the code expects. A
 * legacy login endpoint is the same kind of fact, and declaring it there removes the step
 * where somebody pastes a URL into a console and a secret into an env file, and the two
 * quietly disagree six weeks later.
 *
 * BUT IT IS NOT THE SAME KIND OF RISK, and that difference is the whole design here. A
 * badly declared role harms the app that declared it. A legacy login endpoint sits on the
 * ENVIRONMENT'S sign-in path: every unknown email, and the password typed with it, is
 * offered to whatever URL is on file. A client holding `apps.manifest` that could switch
 * that on by itself would be a credential harvester with a scope for it.
 *
 * So a declaration arrives inert. It is stored, it is shown to an operator beside the app
 * that proposed it, and it does nothing until a person approves it — and re-declaring a
 * DIFFERENT url drops that approval, because "the app changed where passwords go" is
 * exactly the event a human should have to look at.
 */
final readonly class LegacyLoginDeclaration
{
    /** Long enough that the HMAC means something; short enough to paste. */
    private const MIN_SECRET = 32;

    public function __construct(
        public string $url,
        public string $secret,
    ) {
        if (! str_starts_with($url, 'https://')) {
            // Refused at the boundary rather than at call time. A credential in the clear
            // is readable by everything on the path, and no configuration flag anywhere in
            // this feature can permit it.
            throw new InvalidArgumentException('A legacy login URL must be https.');
        }

        if (strlen($secret) < self::MIN_SECRET) {
            // The secret is the only thing proving a request came from us. A short one
            // makes the signature decorative, and a customer who picked "changeme" would
            // otherwise never hear about it.
            throw new InvalidArgumentException(
                'A legacy login secret must be at least '.self::MIN_SECRET.' characters.',
            );
        }
    }

    /**
     * Read a declaration out of a manifest, or null when it carries none.
     *
     * Null and invalid are deliberately different: null means the app said nothing, and
     * invalid throws, because an app that declared something we refused should fail its
     * deploy rather than believe it is migrating when it is not.
     *
     * @param  array<string, mixed>  $raw
     */
    public static function fromArray(array $raw): ?self
    {
        $url = $raw['url'] ?? null;
        $secret = $raw['secret'] ?? null;

        if ($url === null && $secret === null) {
            return null;
        }

        if (! is_string($url) || ! is_string($secret)) {
            throw new InvalidArgumentException('A legacy login declaration needs both a url and a secret.');
        }

        return new self($url, $secret);
    }
}

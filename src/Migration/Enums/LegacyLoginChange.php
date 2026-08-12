<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Enums;

/**
 * What a manifest push did to the environment's legacy-login declaration.
 *
 * A separate value rather than a boolean because the three outcomes are answers to three
 * different questions an operator asks during an incident: nothing happened, an app told
 * us where its old login lives, or an app moved it — and the third is the one that drops
 * an approval and stops every un-migrated sign-in until somebody looks at it.
 */
enum LegacyLoginChange: string
{
    /** No declaration in the manifest, or the same one from the same app. */
    case None = 'none';

    /** A declaration where there was none, awaiting approval. */
    case Declared = 'declared';

    /** The URL or the declaring app changed. Any approval was dropped. */
    case Moved = 'moved';
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Console\Enums;

enum HealthStatus: string
{
    case Ok = 'ok';

    /** Works, but will bite — a default that is fine locally and wrong in production. */
    case Warn = 'warn';

    /** Broken, or configured into a state that cannot do what it claims. */
    case Fail = 'fail';
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Enums;

enum AuthenticationIssuance: string
{
    case Session = 'session';
    case Token = 'token';
}

<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

enum ClientType: string
{
    case Public = 'public';
    case Confidential = 'confidential';
}

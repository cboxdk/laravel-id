<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

enum ConnectionType: string
{
    case Saml = 'saml';
    case Oidc = 'oidc';
}

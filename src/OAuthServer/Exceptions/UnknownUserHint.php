<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A CIBA backchannel request carried a `login_hint` that resolves to no user.
 * The endpoint is client-authenticated, so surfacing this (as the CIBA-spec
 * `unknown_user_id` error) leaks existence only to already-trusted clients.
 */
final class UnknownUserHint extends RuntimeException {}

<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * Why a back-channel logout delivery was abandoned — carried into the queue's failed-job
 * record, so `queue:failed` says the same thing the audit entry does.
 */
class BackchannelLogoutGaveUp extends RuntimeException {}

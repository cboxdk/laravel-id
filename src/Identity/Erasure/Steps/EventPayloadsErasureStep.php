<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure\Steps;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Erasure\PayloadScrubber;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;

/**
 * The domain-event outbox. `user.created` carries the email, `invitation.created` the
 * invitee's address, and delivered rows are kept until `cbox-id:prune` removes them —
 * so the outbox is a second copy of the person unless it is scrubbed.
 *
 * Rewritten in place with {@see PayloadScrubber} (the email and name become the
 * placeholders, everything else stays), constrained to the CURRENT environment: the same
 * address may belong to a different person in another environment.
 */
class EventPayloadsErasureStep implements ErasureStep
{
    use ResolvesEnvironment;

    public function name(): string
    {
        return 'identity.event_payloads';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $environment = $this->environments()->current()?->environmentKey();

        $candidates = PayloadScrubber::mentioningInPayload(Event::query()->where('environment_id', $environment), $request);

        $scrubbed = 0;

        foreach ($candidates->cursor() as $event) {
            $payload = PayloadScrubber::scrub($event->payload, $request);

            if ($payload !== null) {
                $event->payload = $payload;
                $event->save();
                $scrubbed++;
            }
        }

        return ErasureStepResult::of($this->name(), ['events' => $scrubbed]);
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Erasure;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Erasure\PayloadScrubber;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Webhooks\Models\WebhookDelivery;

/**
 * Stored webhook delivery payloads — each a copy of an event, kept for retries and the
 * delivery log. Scrubbed in place with {@see PayloadScrubber}; what was already sent is
 * the receiver's to erase.
 */
class WebhookDeliveriesErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'webhooks.deliveries';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $candidates = PayloadScrubber::mentioningInPayload(WebhookDelivery::query(), $request);

        $scrubbed = 0;

        foreach ($candidates->cursor() as $delivery) {
            $payload = PayloadScrubber::scrub($delivery->payload, $request);

            if ($payload !== null) {
                $delivery->payload = $payload;
                $delivery->save();
                $scrubbed++;
            }
        }

        return ErasureStepResult::of($this->name(), ['webhook_deliveries' => $scrubbed]);
    }
}

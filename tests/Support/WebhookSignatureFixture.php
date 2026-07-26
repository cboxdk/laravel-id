<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support;

use JsonException;

/**
 * Reader for the shared cross-SDK webhook/inline-action signature fixture
 * (`tests/Fixtures/Webhooks/signature.json`). The SAME file is asserted against by
 * id-js, id-python, id-go and laravel-id-client, so it is the single place the
 * sender and the four verifiers agree on the wire format.
 *
 * The point of routing through here rather than writing `$ts.'.'.$body` in a test
 * is that the CONCATENATION ORDER comes from the fixture. A test that re-implements
 * the sender's formula passes even when both sides are flipped together — which is
 * exactly the regression that would break every customer's verification while the
 * whole suite stayed green.
 */
final class WebhookSignatureFixture
{
    /**
     * @return array{signed_payload_template: string, header_template: string, cases: list<array<string, mixed>>}
     *
     * @throws JsonException
     */
    public static function document(): array
    {
        /** @var array{signed_payload_template: string, header_template: string, cases: list<array<string, mixed>>} */
        return json_decode(
            (string) file_get_contents(dirname(__DIR__).'/Fixtures/Webhooks/signature.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }

    /**
     * Every case, keyed by name — ready to hand straight to a Pest dataset.
     *
     * @return array<string, array{0: array<string, mixed>}>
     *
     * @throws JsonException
     */
    public static function dataset(): array
    {
        $dataset = [];

        foreach (self::document()['cases'] as $case) {
            /** @var string $name */
            $name = $case['name'];
            $dataset[$name] = [$case];
        }

        return $dataset;
    }

    /**
     * The `X-Cbox-Signature` value the fixture says a sender must produce for this
     * timestamp, body and secret.
     *
     * @throws JsonException
     */
    public static function expectedHeader(int|string $timestamp, string $body, string $secret): string
    {
        $document = self::document();

        $signedPayload = strtr($document['signed_payload_template'], [
            '{timestamp}' => (string) $timestamp,
            '{body}' => $body,
        ]);

        return strtr($document['header_template'], [
            '{timestamp}' => (string) $timestamp,
            '{signature}' => hash_hmac('sha256', $signedPayload, $secret),
        ]);
    }
}

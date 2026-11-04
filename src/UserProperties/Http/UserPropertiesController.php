<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Http;

use Cbox\Id\UserProperties\Contracts\UserProperties;
use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use JsonException;
use stdClass;

class UserPropertiesController
{
    public function __construct(private readonly UserProperties $properties, private readonly PropertyTokenAccess $access) {}

    public function show(Request $request, string $user, string $namespace): JsonResponse
    {
        return new JsonResponse($this->properties->read($this->access->client($request, $user), $user, $namespace)->toArray());
    }

    public function update(Request $request, string $user, string $namespace): JsonResponse
    {
        $client = $this->access->client($request, $user);
        if (strlen($request->getContent()) > 32768) {
            throw ValidationException::withMessages(['set' => 'A request may contain at most 32 KiB.']);
        }
        $request->validate([
            'version' => ['required', 'integer', 'min:0'],
            'remove' => ['sometimes', 'array', 'list', 'max:100'],
            'remove.*' => ['required', 'string', 'max:128', 'distinct'],
        ]);
        try {
            $body = json_decode($request->getContent(), false, 20, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw ValidationException::withMessages(['set' => 'Use a JSON object.']);
        }
        if (! $body instanceof stdClass || array_diff(array_keys(get_object_vars($body)), ['version', 'set', 'remove']) !== []
            || (property_exists($body, 'set') && ! $body->set instanceof stdClass)) {
            throw ValidationException::withMessages(['set' => 'Use an object with version, set and remove.']);
        }
        $remove = $body->remove ?? [];
        $set = $body->set ?? new stdClass;
        if (! $set instanceof stdClass) {
            throw ValidationException::withMessages(['set' => 'Use a JSON object.']);
        }
        if (! is_array($remove) || ! array_is_list($remove) || ! is_int($body->version ?? null)) {
            throw ValidationException::withMessages(['version' => 'Use an integer version and a list of removed keys.']);
        }
        $keys = [];
        foreach ($remove as $key) {
            if (is_string($key)) {
                $keys[] = $key;
            }
        }

        return new JsonResponse($this->properties->patch($client, $user, $namespace,
            new PropertyPatch($body->version, $set, $keys))->toArray());
    }
}

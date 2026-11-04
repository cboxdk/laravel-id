<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use stdClass;

class PreferenceSchema
{
    public static function validate(stdClass $data): void
    {
        if (property_exists($data, 'week_start') && ! is_int($data->week_start)) {
            throw ValidationException::withMessages(['preferences.week_start' => 'Use an integer from 1 to 7.']);
        }

        Validator::make(['preferences' => get_object_vars($data)], [
            'preferences' => 'array:language,locale,timezone,date_format,time_format,week_start,theme',
            'preferences.language' => ['sometimes', 'string', 'max:35', 'regex:/\A[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*\z/D'],
            'preferences.locale' => ['sometimes', 'string', 'max:35', 'regex:/\A[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*\z/D'],
            'preferences.timezone' => ['sometimes', 'string', 'timezone'],
            'preferences.date_format' => ['sometimes', 'in:locale,yyyy-MM-dd,dd/MM/yyyy,MM/dd/yyyy,dd.MM.yyyy'],
            'preferences.time_format' => ['sometimes', 'in:locale,12h,24h'],
            'preferences.week_start' => ['sometimes', 'integer', 'between:1,7'],
            'preferences.theme' => ['sometimes', 'in:system,light,dark'],
        ])->validate();
    }
}

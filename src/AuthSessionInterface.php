<?php

declare(strict_types=1);

namespace Lengbin\Auth;

interface AuthSessionInterface
{
    /**
     * Returns an attribute.
     *
     * @param string $name The attribute name
     * @param mixed $default The default value if not found
     */
    public function get(string $name, $default = null);

    /**
     * Sets an attribute.
     *
     * @param string $name
     * @param mixed  $value
     */
    public function set(string $name, $value): void;

    /**
     * @param string $name
     *
     * @return mixed
     */
    public function remove(string $name);

    /**
     * @return mixed
     */
    public function destroy();
}

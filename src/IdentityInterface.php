<?php

declare(strict_types=1);

namespace Lengbin\Auth;

interface IdentityInterface
{
    /**
     * Returns an ID that can uniquely identify a user identity.
     * @return string an ID that uniquely identifies a user identity.
     */
    public function getId();
}

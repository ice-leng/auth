<?php

declare(strict_types=1);

namespace Lengbin\Auth\User\Event;

use Lengbin\Auth\IdentityInterface;

class AfterLogoutEvent
{
    private $identity;

    public function __construct(IdentityInterface $identity)
    {
        $this->identity = $identity;
    }

    public function getIdentity(): IdentityInterface
    {
        return $this->identity;
    }
}

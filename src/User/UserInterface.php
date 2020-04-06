<?php

declare(strict_types=1);

namespace Lengbin\Auth\User;

use Lengbin\Auth\AuthSessionInterface;
use Lengbin\Auth\IdentityInterface;

interface UserInterface
{
    /**
     * login
     *
     * @param IdentityInterface $identity
     * @param int               $duration
     *
     * @return mixed
     */
    public function login(IdentityInterface $identity, $duration = 0);

    /**
     * logout
     *
     * @param bool $destroySession
     *
     * @return mixed
     */
    public function logout($destroySession = true);

    /**
     * is Guest
     *
     * @return bool
     */
    public function isGuest();

    /**
     * id
     * @return mixed
     */
    public function getId();

    /**
     * Identity
     *
     * @param bool $autoRenew
     *
     * @return mixed
     */
    public function getIdentity($autoRenew = true);

    /**
     * permission
     *
     * @param string $permissionName
     * @param array  $params
     *
     * @return mixed
     */
    public function can(string $permissionName, array $params = []);

    /**
     * Set session to persist authentication status across multiple requests.
     * If not set, authentication has to be performed on each request, which is often the case
     * for stateless application such as RESTful API.
     *
     * @param $session
     */
    public function setSession(AuthSessionInterface $session): void;

    /**
     * @param AccessCheckerInterface $accessChecker
     */
    public function setAccessChecker(AccessCheckerInterface $accessChecker): void;
}

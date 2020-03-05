<?php
declare(strict_types=1);

namespace Lengbin\Hyperf\Auth\Middleware;

use Lengbin\Hyperf\Auth\IdentityInterface;
use Lengbin\Hyperf\Auth\IdentityRepositoryInterface;
use Lengbin\Hyperf\Auth\Method\CompositeAuth;
use Lengbin\Hyperf\Auth\User\GuestIdentity;
use Lengbin\Hyperf\Auth\User\User;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Class AuthMiddleware
 * thanks yii
 * @package Common\middleware\auth
 */
class Auth
{

    private const REQUEST_NAME = 'auth';

    private $requestName = self::REQUEST_NAME;

    /**
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var array
     */
    protected $config;

    /**
     * Auth constructor.
     *
     * @param ContainerInterface $container
     * @param array              $config
     */
    public function __construct(ContainerInterface $container, array $config)
    {
        $this->config = $this->checkConfig($config);
        $this->setRequestName(ArrayHelper::getValue($config, 'requestName', self::REQUEST_NAME));
        $this->container = $container;
    }

    /**
     * request name
     *
     * @param string $name
     */
    public function setRequestName(string $name): void
    {
        $this->requestName = $name;
    }

    /**
     * @param $config
     *
     * @return mixed
     */
    protected function checkConfig($config)
    {
        if ($config === null) {
            throw new InvalidArgumentException('Please set auth config');
        }

        if (empty($config['method'])) {
            throw new InvalidArgumentException('Please set auth config method params');
        }

        if (!is_string($config['method']) && !is_array($config['method'])) {
            throw new InvalidArgumentException('Method params support string and array');
        }

        return $config;
    }

    public function getIdentity(RequestInterface $request, $isPublic = null, $isWhitelist = null): IdentityInterface
    {
        $auth = $this->config;

        //不验证
        if ($isPublic === null) {
            $publicList = ArrayHelper::getValue($auth, 'public', []);
            $isPublic = $this->checkPath($request, $publicList);
        }

        $guestIdentity = new GuestIdentity();

        if ($isPublic) {
            return $guestIdentity;
        }

        //白名单
        if ($isWhitelist === null) {
            $whitelist = ArrayHelper::getValue($auth, 'whitelist', []);
            $isWhitelist = $this->checkPath($request, $whitelist);
        }

        $method = $auth['method'];
        if (is_array($method)) {
            $authenticator = new CompositeAuth($this->container);
            $authenticator->setAuthMethods($method);
        } else {
            $authenticator = new $method($this->container->get(IdentityRepositoryInterface::class));
            if (!$authenticator instanceof AuthInterface) {
                throw new \RuntimeException(get_class($authenticator) . ' must implement ' . AuthInterface::class);
            }
        }

        $identity = $authenticator->authenticate($request) ?? $guestIdentity;
        $user = new User($this->container, $identity);
        $user->login($identity);

        if (!$isWhitelist && !$identity->getId()) {
            throw new InvalidTokenException();
        }
        return $user;
    }

    /**
     * check url path
     *
     * @param ServerRequestInterface $request
     * @param array                  $patterns
     *
     * @return bool
     */
    protected function checkPath(ServerRequestInterface $request, array $patterns = []): bool
    {
        $status = false;
        $path = $request->getUri()->getPath();
        foreach ($patterns as $pattern) {
            if (StringHelper::matchWildcard($pattern, $path)) {
                $status = true;
                break;
            }
        }
        return $status;
    }
}

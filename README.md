# Auth

感谢yii3

Install
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
composer require lengbin/auth
```

or add

```
"lengbin/auth": "*"
```
to the require section of your `composer.json` file.


如果没有看懂可以参考[hyper-helper](https://github.com/ice-leng/hyperf-auth.git)

Usage
-----
```php
// 中间件
class ApiMiddleware extends AbstractAuth implements MiddlewareInterface
{
    /**
     * @inheritDoc
     */
    public function getConfig(): array
    {
        return [
              // 全局变量 名称
              'requestName'   => 'api',
              // 实现类，请实现接口 \Lengbin\Auth\IdentityRepositoryInterface::class
              'identityClass' => User::class,
              // 验证器方法，支持
              // header: \Lengbin\Auth\Method\HttpHeaderAuth::class
              // query : \Lengbin\Auth\Method\QueryParamAuth::class
              // sign  : \Lengbin\Auth\Method\SignAuth::class
              // 如果为 数组 则为 混合验证
              'method' => [
                  \Lengbin\Auth\Method\HttpHeaderAuth::class,
                  \Lengbin\Auth\Method\QueryParamAuth::class,
              ],
              //路由白名单。列如 /test/{id}, 可以使用*来通配, /test/*
              'whitelist'     => [],
              //公共访问，不走验证。列如 /test/{id}, 可以使用*来通配, /test/*
              'public'        => [],
          ];
    }

    /**
     * Process an incoming server request.
     *
     * Processes an incoming server request in order to produce a response.
     * If unable to produce the response itself, it may delegate to the provided
     * request handler to do so.
     *
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     *
     * @return ResponseInterface
     * @throws \Lengbin\Auth\Exception\InvalidTokenException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $isPublic = $this->checkPublicList($path);
        $isWhitelist = $this->checkWhitelist($path);
        $user = $this->getUser($request, $isPublic, $isWhitelist);
        $request->withAttribute($this->requestName, $user);
        return $handler->handle($request);
    }
}
```


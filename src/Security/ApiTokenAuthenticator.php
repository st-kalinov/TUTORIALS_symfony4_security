<?php

namespace App\Security;

use App\Repository\ApiTokenRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class ApiTokenAuthenticator extends AbstractGuardAuthenticator
{

    /**
     * @var ApiTokenRepository
     */
    private $apiTokenRepo;

    public function __construct(ApiTokenRepository $apiTokenRepo)
    {

        $this->apiTokenRepo = $apiTokenRepo;
    }

    public function supports(Request $request)
    {
        return $request->headers->has('Authorization')
            && 0 === strpos($request->headers->get('Authorization'), 'Bearer ');
    }

    public function getCredentials(Request $request)
    {
        $authorizationHeader = $request->headers->get('Authorization');

        return substr($authorizationHeader, 7);
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = $this->apiTokenRepo->findOneBy(['token' => $credentials]);

        if(!$token)
        {
            throw new CustomUserMessageAuthenticationException('Invalid API Token');
        }
        if($token->isExpired())
        {
            throw new CustomUserMessageAuthenticationException('Token is expired!');
        }
        return $token->getUser();
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new JsonResponse([
           'message' => $exception->getMessageKey()
        ], 401);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // todo
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        //nqma da e izvikano nikoga, zashtoto sme izbrali EntryPoint da e 'LoginFormAuthenticator, a tam clasa koito se nasledqva nqma tozi 'start' metod.
    }

    public function supportsRememberMe()
    {
        // ako returnem true ozn che remember me systemata e aktivirana i shte proveri checkboxa za remember me dali e checknata, no tova nqma nikakyv smisal s
        // API token avtentifikaciq, za tova vryshtame false

        return false;
    }
}

<?php

namespace SocialiteProviders\Xbox;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User as User;

class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'XBOX';

    /**
     * {@inheritdoc}
     * https://msdn.microsoft.com/en-us/library/azure/ad/graph/howto/azure-ad-graph-api-permission-scopes.
     */
    protected $scopes = ['Xboxlive.signin', 'Xboxlive.offline_access'];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return
            $this->buildAuthUrlFromBase(
                'https://login.live.com/oauth20_authorize.srf',
                $state
            );
    }

    /**
     * {@inheritdoc}
     * https://developer.microsoft.com/en-us/graph/docs/concepts/use_the_api.
     */
    protected function getTokenUrl()
    {
        return 'https://login.live.com/oauth20_token.srf';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        // get user token
        $response = $this->getHttpClient()->post('https://user.auth.xboxlive.com/user/authenticate', [
            'headers' => [
                'x-xbl-contract-version' => 1
            ],
            'json' => [
                "RelyingParty" => "http://auth.xboxlive.com",
                "TokenType" => "JWT",
                "Properties" => [
                    "AuthMethod" => "RPS",
                    "SiteName" => "user.auth.xboxlive.com",
                    "RpsTicket" => 'd=' . $token
                ],
            ]
        ]);

        $user_token = json_decode($response->getBody()->getContents(), true);

        // get XSTS token
        $response = $this->getHttpClient()->post('https://xsts.auth.xboxlive.com/xsts/authorize', [
            'headers' => ['x-xbl-contract-version' => 1],
            'json' => [
                "RelyingParty" => "http://xboxlive.com",
                "TokenType" => "JWT",
                "Properties" => [
                    "UserTokens" => [$user_token['Token']]
                ],
                "SandboxId" => "RETAIL"
            ]
        ]);

        $xsts_token = json_decode($response->getBody()->getContents(), true);

        // get profile data
        $response = $this->getHttpClient()->post('https://profile.xboxlive.com/users/batch/profile/settings', [
            'json' => [
                'userIds' => [
                    $xsts_token['DisplayClaims']['xui'][0]['xid']
                ],
                'settings' => [
                    'GameDisplayName',
                    'GameDisplayPicRaw',
                    'Gamerscore',
                    'Gamertag',
                    'AppDisplayName',
                    'AppDisplayPicRaw',
                    'AccountTier',
                    'TenureLevel',
                ]
            ],
            'headers' => [
                'x-xbl-contract-version' => 2,
                'Authorization' => 'XBL3.0 x=' . $xsts_token['DisplayClaims']['xui'][0]['uhs'] . ';' . $xsts_token['Token']
            ]
        ]);
        $users = json_decode($response->getBody()->getContents(), true);
        $user = [
            'xuid' => $users['profileUsers'][0]['id'],
        ];
        foreach ($users['profileUsers'][0]['settings'] as $setting) {
            $user[$setting['id']] = $setting['value'];
        }
        // export profile data with xsts token
        $user['xsts_token'] = $xsts_token;
        return $user;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'       => $user['xuid'],
            'nickname' => $user['GameDisplayName'],
            'avatar' => $user['GameDisplayPicRaw'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
            'scope'      => parent::formatScopes(parent::getScopes(), $this->scopeSeparator),
            'response_type' => 'code'
        ]);
    }

    /**
     *
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return [
            'response_type' => 'code',
            'approval_prompt' => 'auto',
        ];
    }
}

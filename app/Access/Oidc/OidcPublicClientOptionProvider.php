<?php

namespace BookStack\Access\Oidc;

use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;

/**
 * Option provider for public OIDC clients (PKCE, no client secret).
 * Extends PostAuthOptionProvider but removes client_secret from the
 * token request body, since public clients do not authenticate with a secret.
 */
class OidcPublicClientOptionProvider extends PostAuthOptionProvider
{
    public function getAccessTokenOptions($method, array $params)
    {
        unset($params['client_secret']);
        return parent::getAccessTokenOptions($method, $params);
    }
}

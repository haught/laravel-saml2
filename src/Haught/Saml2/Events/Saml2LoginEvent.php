<?php

namespace Haught\Saml2\Events;

use Haught\Saml2\Saml2User;
use Haught\Saml2\Saml2Auth;

class Saml2LoginEvent extends Saml2Event {

    protected $user;
    protected $auth;

    function __construct($idp, Saml2User $user, Saml2Auth $auth)
    {
        parent::__construct($idp);
        $this->user = $user;
        $this->auth = $auth;
    }

    public function getSaml2User()
    {
        return $this->user;
    }

    public function getSaml2Auth()
    {
        return $this->auth;
    }
}

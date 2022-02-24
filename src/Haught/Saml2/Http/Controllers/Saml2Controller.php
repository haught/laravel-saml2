<?php

namespace Haught\Saml2\Http\Controllers;

use Haught\Saml2\Events\Saml2LoginEvent;
use Haught\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redirect;
use App\Providers\RouteServiceProvider;

class Saml2Controller extends Controller
{

    protected $saml2Auth;
    protected $idp;

    /**
     * Add needed superglobals for php-saml that swoole does not provide
     *
     * @param Request $request
     *
     * @return void
     */
    private function setRequest(Request $request)
    {
        $_POST['SAMLResponse'] = array_key_exists('SAMLResponse', $request->post()) ? $request->post()['SAMLResponse'] : null;
        $_GET['SAMLResponse'] = array_key_exists('SAMLResponse', $request->query()) ? $request->query()['SAMLResponse'] : null;
        $_GET['SAMLRequest'] = array_key_exists('SAMLRequest', $request->query()) ? $request->query()['SAMLRequest'] : null;
        $_GET['RelayState'] = array_key_exists('RelayState', $request->query()) ? $request->query()['RelayState'] : null;
        $_GET['Signature'] = array_key_exists('Signature', $request->query()) ? $request->query()['Signature'] : null;
        $_REQUEST['RelayState'] = array_key_exists('RelayState', $request->all()) ? $request->all()['RelayState'] : null;
        if (!empty($request->server->get('HTTP_X_FORWARDED_PROTO'))) {
            $_SERVER['HTTP_X_FORWARDED_PROTO'] = $request->server->get('HTTP_X_FORWARDED_PROTO');
        }
        if (!empty($request->server->get('HTTP_X_FORWARDED_HOST'))) {
            $_SERVER['HTTP_X_FORWARDED_HOST'] = $request->server->get('HTTP_X_FORWARDED_HOST');
        } else {
            $_SERVER['HTTP_HOST'] = parse_url(config('app.url'), PHP_URL_HOST);
        }
    }

    /**
     * Remove superglobals that were needed for php-saml that swoole does not provide
     *
     *
     * @return void
     */
    private function unsetRequest()
    {
        unset(
            $_POST['SAMLResponse'],
            $_GET['SAMLResponse'],
            $_GET['SAMLRequest'],
            $_GET['RelayState'],
            $_GET['Signature'],
            $_REQUEST['RelayState'],
            $_SERVER['HTTP_X_FORWARDED_PROTO'],
            $_SERVER['HTTP_X_FORWARDED_HOST'],
            $_SERVER['HTTP_HOST'],
        );
    }

    /**
     * Generate local sp metadata.
     *
     * @param Saml2Auth $saml2Auth
     * @return \Illuminate\Http\Response
     */
    public function metadata(Saml2Auth $saml2Auth)
    {
        $metadata = $saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is found.
     *
     * @param Saml2Auth $saml2Auth
     * @param $idpName
     * @param Request $request
     * @return \Illuminate\Http\Response
     */
    public function acs(Saml2Auth $saml2Auth, $idpName, Request $request)
    {
        $this->setRequest($request);
        $errors = $saml2Auth->acs();

        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }
        $user = $saml2Auth->getSaml2User();

        event(new Saml2LoginEvent($idpName, $user, $saml2Auth));

        $redirectUrl = $user->getIntendedUrl();

        $this->unsetRequest();

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } else {

            return redirect(config('saml2_settings.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'Saml2LogoutEvent' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log them out locally too.
     *
     * @param Saml2Auth $saml2Auth
     * @param $idpName
     * @return \Illuminate\Http\Response
     */
    public function sls(Saml2Auth $saml2Auth, $idpName, Request $request)
    {
        $this->setRequest($request);
        $errors = $saml2Auth->sls($idpName, config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($errors)) {
            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            throw new \Exception("Could not log out");
        }

        $this->unsetRequest();

        return redirect(config('saml2_settings.logoutRoute')); //may be

    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     *
     * @param Saml2Auth $saml2Auth
     * @param Request $request
     */
    public function logout(Saml2Auth $saml2Auth, Request $request)
    {
        $this->setRequest($request);
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
        $nameId = $request->query('nameId');
        // swoole can't handle exit() or headers(), manually redirect via laravel
        $redirectTo = $saml2Auth->logout($returnTo, $nameId, $sessionIndex, null, true);
        $this->unsetRequest();
        Log::debug('SAML Logout request received');
        \Auth::logout();
        return redirect($redirectTo);
    }

    /**
     * This initiates a login request
     *
     * @param Saml2Auth $saml2Auth
     * @param Request $request
     */
    public function login(Saml2Auth $saml2Auth, Request $request)
    {
        $this->setRequest($request);
        // swoole can't handle exit() or headers(), manually redirect via laravel
        $redirectTo = $saml2Auth->login(Redirect::intended(RouteServiceProvider::HOME)->getTargetUrl(), [], false, false, true);
        $this->unsetRequest();
        Log::debug('SAML Login request received');
        return redirect($redirectTo);
    }
}

import logging
from urlparse import urlparse
from django.conf import settings
from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse
from social_django.utils import load_strategy
from backends.esgf import discover
from urllib import quote
from crypto_cookie.encoding import Encoder
from crypto_cookie.auth_tkt import SecureCookie


log = logging.getLogger(__name__)


'''
The home view corresponds to /esg-orp/home.htm, however it supports both OpenID
and OAuth2.
'''
def home(request):
    if request.method == 'GET':
        '''
        requested directly or
        redirected from THREDDS/authentication filter or
        redirected from OpenID/OAuth2 server or
        '''
        if request.user.is_authenticated():
            social = None
            try:
                social = request.user.social_auth.get(provider='esgf')
            except Exception:
                pass

            try:
                social = request.user.social_auth.get(provider='esgf-openid')
            except Exception:
                pass

            log.info('User {} successfully authenticated'.format(social.uid))

            redirect_url = request.GET.get('redirect', request.session.get('redirect'))

            if not redirect_url:
                '''
                not redirected from THREDDS/authentication filter
                '''
                return render(request,
                        'auth/home.j2', {
                            'openid_identifier': social.uid
                        })
            '''
            redirected from OpenID/OAuth2 server or
            redirected from THREDD/authentication filter
            '''
            # create a session cookie
            encoded_secret_key = settings.ESGF_SECRET_KEY
            session_cookie_name = settings.ESGF_SESSION_COOKIE_NAME
            secret_key = encoded_secret_key.decode('base64')
            secure_cookie = SecureCookie(
                    secret_key, social.uid, '127.0.0.1', (), '')

            # redirect back to THREDDS
            response = redirect(redirect_url)
            response.set_cookie(
                    session_cookie_name, secure_cookie.cookie_value())
            return response

        else:
            '''
            requested directly or
            redirected from THREDDS/authentication filter
            '''
            redirect_url = request.GET.get('redirect')

            '''
            Save 'redirect' param passed in the redirection by the THREDDS 
            authentication filter before starting the OAuth2 flow. After the 
            OAuth2 flow is completed, the param will be needed to create a 
            redirection back to THREDDS.
            '''
            request.session['redirect'] = redirect_url

            return render(request,
                    'auth/home.j2', {
                        'redirect': redirect_url
                    })

    # request.method == 'POST'
    openid_identifier = request.POST.get('openid_identifier')
    request.session['openid_identifier'] = openid_identifier
    print 'OpenID', openid_identifier
    protocol = discover(openid_identifier)
    print 'Protocol', protocol
    if protocol:
        request.session['next'] = request.path
        parsed_openid = urlparse(openid_identifier)
        credential = settings.SOCIAL_AUTH_ESGF.get(parsed_openid.netloc)
        if protocol == 'OAuth2' and credential:
            '''
            It may create a race condition.  When two users authenticate at the
            same moment  through different OAuth2 servers, KEY and SECRET may
            be set for a wrong server. It will be better to set KEY and SECRET
            directly on a strategy object.
            '''
            settings.SOCIAL_AUTH_ESGF_KEY = credential['key']
            settings.SOCIAL_AUTH_ESGF_SECRET = credential['secret']
            print 'tutaj 1'
            return redirect(reverse('social:begin', args=['esgf']))
        elif protocol == 'OpenID':
            print 'tutaj 2'
            return redirect(reverse('social:begin', args=['esgf-openid']))
    else:
        print 'tutaj 3'
        log.error('Could not discover authentication service for {}'.format(openid_identifier))
        return render(request,
                'auth/home.j2', {
                    'redirect': redirect_url,
                    'message': 'No OpenID/OAuth2/OIDC service discovered'
                })


'''
A test view to mimic THREDDS/authentication filter. On ESGF systems with
THREDDS deployed, Apache is configured as a reverse proxy for the '/thredds'
path and this view is not be accessible.
'''
def thredds(request):
    encoded_secret_key = settings.ESGF_SECRET_KEY
    return_query_name = settings.ESGF_RETURN_QUERY_NAME
    session_cookie_name = settings.ESGF_SESSION_COOKIE_NAME

    if request.is_secure():
        scheme = 'https'
    else:
        scheme = 'http'
    authenticate_url = '{}://{}{}'.format(scheme, request.get_host(), reverse('home'))
    redirect = '{}://{}{}{}'.format(scheme, request.get_host(), reverse('thredds'), 'fileServer/cmip5_css02_data/cmip5/output1/CMCC/CMCC-CM/historical/day/atmos/day/r1i1p1/clt/1/clt_day_CMCC-CM_historical_r1i1p1_20050101-20051231.nc')

    session_cookie = request.COOKIES.get(session_cookie_name)
    cookie = None
    if session_cookie:
        secret_key = encoded_secret_key.decode('base64')
        cookie = SecureCookie.parse_ticket(secret_key, session_cookie, None, None)

    return render(request,
            'auth/thredds.j2', {
                'authenticate_url': authenticate_url,
                'return_query_name': return_query_name,
                'encoded_secret_key': encoded_secret_key,
                'quoted_encoded_secret_key': quote(encoded_secret_key),
                'session_cookie_name': session_cookie_name,
                'redirect': redirect,
                'session_cookie': session_cookie,
                'decrypted_session_cookie': cookie
            })


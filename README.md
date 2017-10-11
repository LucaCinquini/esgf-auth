# esgf-auth
OpenID/OAuth2 authentication client for ESGF

The ESGF authentication client is a Django web aplication that replaces the 
ESGF ORP. If a dataset file requires authentication, the THREDDS 
authentication filter redirects a user web browser to the web app. The web
app discovers authentication services provided by an IdP selected by a user
in the drop down, and redirects the user web browser to OAuth2 or OpenID
server where the user enters his/her username and password. When the user 
is authenticated successfully, the OAuth2 (or OpenID) server redirects the 
user web browser back to the web app. The web app sets a secret cookie and
redirects the user back to the THREDDS authentication filter.

# Install esgf-auth

Create Python 2.7 virtual environment
```
$ python --version 
Python 2.7.10
$ virtualenv venv
$ . venv/bin/activate
```
Download and install crypto-cookie:
```
(venv)$ git clone git@github.com:philipkershaw/crypto-cookie
(venv)$ cd crypto-cookie
(venv)$ python setup.py
(venv)$ cd ..
```
Download and install esgf-auth with dependencies (Django, 
social-auth-app-django, social-auth-core, etc.)
```
(venv)$ git clone git@github.com:lukaszlacinski/esgf-auth
(venv)$ cd esgf-auth
(venv)$ pip install -r requirements.txt
```
Create the database
```
(venv)$ ./manage.py migrate
```
Create /esg/config/esgf_oauth2.json file with a client key and secret 
received from an admin of an ESGF OAuth2 server. When you register your 
OAuth2 client, your redirect URI is 
`https://<your_hostname>/esgf-auth/complete/esgf/`. Here is a sample
esgf_oauth2.json file:
```
{
    "ceda.ac.uk":
        "key": "BUwBQaqS7qs2pSLhwHiAQlqt+hc=",
        "secret": "Qf+EsAoDmZzdW1L/H4zAj2u/tg3ISCnqxby+2bD7hY/GCZcRJgUjFQ=="
    },
    "esgf-node.llnl.gov": {
        "key": "RMRXIub0/m4RIfo7sdr2OiGOTmc=",
        "secret": "N9PT+3/rGnjGPkEBsyzhoggsyFYdX6ptPG9Gy6Olb0j8ub/4+DJtiA=="
    }
}
```

# Apache/mod_wsgi

For example, on Ubuntu, add the following lines to 
/etc/apache2/sites-available/default-ssl,conf in 
`<VirtualHost _default_:443>`

```
    WSGIDaemonProcess esgf_auth python-path=<your_base_dir>/esgf-auth:<your_base_dir>/venv/lib/python2.7/site-packages
    WSGIScriptAlias /esgf-auth <your_base_dir>/esgf-auth/esgf_auth/wsgi.py process-group=esgf_auth
    <Directory <your_base_dir>/esgf-auth/esgf_auth>
        <Files wsgi.py>
            # Apache >= 2.4
            #Require all granted
            # Apache <= 2.2
            Order allow,deny
            Allow from all
        </Files>
    </Directory>
    Alias /esgf-auth/home/static/ <your_base_dir>/esgf-auth/static/
    <Directory <your_base_dir>/esgf-auth/static>
        Options -Indexes
        # Apache >= 2.4
        #Require all granted
        # Apache <= 2.2
        Order allow,deny
        Allow from all
        AllowOverride None
    </Directory>
```
After restarting Apache, open `https://<your_hostname>/esgf-auth/thredds/` 
in a web browser. The page mimics THREDDS server with the authentication 
filter. You will also likely need to change ownership of the 'esgf-auth' directory to 
www-data (on Ubuntu), so Apache can access the SQLite3 database file.

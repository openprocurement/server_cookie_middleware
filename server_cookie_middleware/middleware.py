from Cookie import SimpleCookie
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from datetime import datetime
from logging import getLogger
from os import environ
from oslo_middleware import base
from pytz import timezone
from webob.dec import wsgify
from webob.exc import HTTPPreconditionFailed


LOGGER = getLogger(__name__)
TZ = timezone(environ['TZ'] if 'TZ' in environ else 'Europe/Kiev')


def get_time():
    return datetime.now(TZ).isoformat()


def encrypt(mid, bid):
    time = get_time()
    text = "{}{:^{}}".format(bid, time, AES.block_size * 2)
    return hexlify(AES.new(mid).encrypt(text)), time


def decrypt(mid, key):
    try:
        text = AES.new(mid).decrypt(unhexlify(key))
    except:
        text = ''
    return text


class ServerCookieMiddleware(base.Middleware):
    """
    It ensures to assign server id for each HTTP request.
    [filter:server_cookie]
    paste.filter_factory = server_cookie_middleware.middleware:ServerCookieMiddleware.factory
    cookie_name = SERVER_ID
    """

    @classmethod
    def factory(cls, global_conf,
                cookie_name='SID'):
        cls.cookie_name = cookie_name
        with open('/etc/machine-id') as f:
            cls.m_id = f.read().strip()
        with open('/proc/sys/kernel/random/boot_id') as f:
            cls.b_id = ''.join(f.read().strip().split('-'))
        return cls

    @wsgify
    def __call__(self, req):
        C = SimpleCookie(req.environ.get('HTTP_COOKIE'))
        server_id = C.get(self.cookie_name, None)
        if server_id:
            value = server_id.value
            decrypted = decrypt(self.m_id, value)
            if not decrypted or not decrypted.startswith(self.b_id):
                LOGGER.info("Invalid cookie: %s", value, extra={'MESSAGE_ID': 'serverid_invalid'})
                value, time = encrypt(self.m_id, self.b_id)
                C = SimpleCookie()
                C[self.cookie_name] = value
                C[self.cookie_name]['path'] = '/'
                LOGGER.info("New cookie: %s (%s)", value, time, extra={'MESSAGE_ID': 'serverid_new'})
                response = HTTPPreconditionFailed(headers={'Set-Cookie': C[self.cookie_name].OutputString()})
                response.empty_body = True
                raise response
            else:
                time = decrypted[len(self.b_id):]
                LOGGER.debug("Valid cookie: %s (%s)", value, time, extra={'MESSAGE_ID': 'serverid_valid'})
        response = req.get_response(self.application)
        if not server_id:
            value, time = encrypt(self.m_id, self.b_id)
            C = SimpleCookie()
            C[self.cookie_name] = value
            C[self.cookie_name]['path'] = '/'
            LOGGER.info("New cookie: %s (%s)", value, time, extra={'MESSAGE_ID': 'serverid_new'})
            response.headers.add('Set-Cookie', C[self.cookie_name].OutputString())
        return response

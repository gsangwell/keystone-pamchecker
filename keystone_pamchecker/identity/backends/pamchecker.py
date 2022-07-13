from keystone.identity.backends import sql

from oslo_log import log
LOG = log.getLogger(__name__)

import socket

class Identity(sql.Identity):
    def _check_password(self, password, user_ref):
        username = user_ref.get('name')

        if super(Identity, self)._check_password(password, user_ref):
            LOG.debug('authentication via DB succeeded')
            return True
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(('127.0.0.1',8317))
                    s.sendall(bytes("%s %s\r\n" % (username, password), 'utf-8'))
                    data = s.recv(1024).decode('utf-8').rstrip()
                LOG.debug('authentication via PAM reports: %s' % (data))
                return data == "ok"
            except:
                return False

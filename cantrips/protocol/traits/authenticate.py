from cantrips.patterns.actions import AccessControlledAction
from cantrips.protocol.traits.permcheck import PermCheck
from cantrips.protocol.traits.provider import IProtocolProvider


class Authenticate(PermCheck, IProtocolProvider):
    """
    This authenticator will be in front of a master IBroadcast.
    It will be the one with the power to:
      * let a socket authenticate.
      * let a socket de-authenticate.
      * forcefully de-authenticate a socket.
    This class is intended to be used along with UserEndpoint,
      UserBroadcast, and MessageProcessor classes.
    """

    AUTHENTICATE_NS = 'auth'
    AUTHENTICATE_CODE_FORCED_LOGOUT = 'logged-out'

    AUTHENTICATE_RESPONSE_NS = 'notify'
    AUTHENTICATE_RESPONSE_CODE_RESPONSE = 'response'

    AUTHENTICATE_RESULT_DENY_NO_ACTIVE_SESSION = 'no-active-session'
    AUTHENTICATE_RESULT_DENY_ALREADY_ACTIVE_SESSION = 'already-active-session'
    AUTHENTICATE_RESULT_DENY_INVALID = 'invalid-login'
    AUTHENTICATE_RESULT_ALLOW_LOGGED_IN = 'logged-in'
    AUTHENTICATE_RESULT_ALLOW_LOGGED_OUT = 'logged-out'

    @classmethod
    def specification(cls):
        return {
            cls.AUTHENTICATE_NS: {
                cls.AUTHENTICATE_CODE_FORCED_LOGOUT: 'client'
            },
            cls.AUTHENTICATE_RESPONSE_NS: {
                cls.AUTHENTICATE_RESPONSE_CODE_RESPONSE: 'client'
            }
        }

    login = AccessControlledAction(
        lambda obj, socket, *args, **kwargs: obj._login_command_is_allowed(socket, *args, **kwargs),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket, *args, **kwargs: obj._login_command_on_accepted(result, socket, *args, **kwargs),
        lambda obj, result, socket, *args, **kwargs: obj._login_command_on_rejected(result, socket, *args, **kwargs),
    ).as_method("""
    Allows sockets to log-in to the server. Its check (_login_command_is_allowed) MUST be implemented.
    """)

    logout = AccessControlledAction(
        lambda obj, socket, *args, **kwargs: obj._logout_command_is_allowed(socket, *args, **kwargs),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket, *args, **kwargs: obj._logout_command_on_accepted(result, socket, *args, **kwargs),
        lambda obj, result, socket, *args, **kwargs: obj._logout_command_on_rejected(result, socket, *args, **kwargs),
    ).as_method("""
    Allows sockets to log-out from the server.
    """)

    def force_logout(self, user, *args, **kwargs):
        """
        Logs a user out, by key. The user will be notified. Since this
          command is not executed by the client, it must return a boolean
          value indicating whether the user was logged in or not.
        """
        if user in self._broadcast.users():
            user = self._broadcast.users()[user]
            self._broadcast.unregister(user, *args, **kwargs)
            del user.socket.user_endpoint
            user.socket.send_message(self.AUTHENTICATE_NS, self.AUTHENTICATE_CODE_FORCED_LOGOUT, *args, **kwargs)
            return True
        else:
            return False

    def __init__(self):
        """
        Instantiates a master broadcast, which will be used.
        """
        klass = self.main_broadcast_class()
        key, kwargs = self.main_broacast_args()
        kwargs['master'] = True
        self._broadcast = klass(key, **kwargs)

    def main_broadcast_class(self):
        """
        Provides the class to use as master broadcast.
        """
        raise NotImplementedError

    def main_broacast_args(self):
        """
        Provides the arguments used to instantiate a master broadcast.
        You should return a tuple (key, kwargs). If you specify `master`
          as item in kwargs, it will be ignored.
        """
        raise NotImplementedError

    def _login(self, socket, *args, **kwargs):
        """
        Performs log-in. Should return a triple:
          (user key, user args, user kwargs).
        """
        raise NotImplementedError

    def _login_command_is_allowed(self, socket, *args, **kwargs):
        """
        Checks whether a user must be allowed, or not, to log-in (e.g. bad user/password).
        """
        user = getattr(socket, 'user_endpoint')
        if user and user in self._broadcast.users():
            return self._result_deny(self.AUTHENTICATE_RESULT_DENY_ALREADY_ACTIVE_SESSION)
        else:
            return self._login(socket, *args, **kwargs) or self._result_deny(self.AUTHENTICATE_RESULT_DENY_INVALID)

    def _login_command_on_accepted(self, result, socket, *args, **kwargs):
        """
        Accepts the login attempt and registers the user in the broadcast.
        """
        user_key, user_args, user_kwargs = result
        self._broadcast.register(user_key, *user_args, **user_kwargs)
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)

    def _login_command_on_rejected(self, result, socket, *args, **kwargs):
        """
        Rejects the login attempt with the gotten result.
        """
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)

    def _logout_command_is_allowed(self, socket, *args, **kwargs):
        """
        Checks whether the socket should be allowed to logout.
        """
        user = getattr(socket, 'user_endpoint')
        if user and user in self._broadcast.users():
            return self._result_allow(self.AUTHENTICATE_RESULT_ALLOW_LOGGED_OUT)
        else:
            return self._result_deny(self.AUTHENTICATE_RESULT_DENY_NO_ACTIVE_SESSION)

    def _logout_command_on_accepted(self, result, socket, *args, **kwargs):
        """
        Accepts the logout command and cleans the user_endpoint.
        """
        self._broadcast.unregister(socket.user_endpoint, *args, **kwargs)
        del socket.user_endpoint
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)

    def _logout_command_on_rejected(self, result, socket, *args, **kwargs):
        """
        Rejects the logout command, and cleans the user_endpoint (perhaps an expired session exists).
        """
        if hasattr(socket, 'user_endpoint'):
            del socket.user_endpoint
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)
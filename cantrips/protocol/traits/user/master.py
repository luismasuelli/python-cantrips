from cantrips.iteration import items
from cantrips.patterns.identify import List
from cantrips.patterns.actions import AccessControlledAction
from base import UserBroadcast
from cantrips.protocol.traits.provider import IProtocolProvider


class UserMasterBroadcast(UserBroadcast, IProtocolProvider):
    """
    This broadcast creates a user - it supports login features.
    """

    AUTHENTICATE_NS = 'auth'
    AUTHENTICATE_CODE_LOGIN = 'login'
    AUTHENTICATE_CODE_LOGOUT = 'logout'
    AUTHENTICATE_CODE_FORCED_LOGOUT = 'logged-out'

    AUTHENTICATE_RESPONSE_NS = 'notify'
    AUTHENTICATE_RESPONSE_CODE_RESPONSE = 'response'

    AUTHENTICATE_RESULT_DENY_NO_ACTIVE_SESSION = 'no-active-session'
    AUTHENTICATE_RESULT_DENY_ALREADY_ACTIVE_SESSION = 'already-active-session'
    AUTHENTICATE_RESULT_DENY_INVALID = 'invalid-login'
    AUTHENTICATE_RESULT_ALLOW_LOGGED_IN = 'logged-in'
    AUTHENTICATE_RESULT_ALLOW_LOGGED_OUT = 'logged-out'

    CHANNEL_NS = 'channel'
    CHANNEL_CODE_CREATE = 'create'
    CHANNEL_CODE_CLOSE = 'close'
    CHANNEL_CODE_JOIN = 'join'
    CHANNEL_CODE_PART = 'part'

    CHANNEL_RESPONSE_NS = 'notify'
    CHANNEL_RESPONSE_CODE_RESPONSE = 'response'

    CHANNEL_RESULT_DENY_CREATE = 'cannot-create-channel'
    CHANNEL_RESULT_DENY_CLOSE = 'cannot-close-channel'
    CHANNEL_RESULT_DENY_UNEXISTENT = 'unexistent-channel'

    @classmethod
    def specification(cls):
        return {
            cls.AUTHENTICATE_NS: {
                cls.AUTHENTICATE_CODE_LOGIN: 'server',
                cls.AUTHENTICATE_CODE_LOGOUT: 'server',
                cls.AUTHENTICATE_CODE_FORCED_LOGOUT: 'client'
            },
            cls.CHANNEL_NS: {
                cls.CHANNEL_CODE_CREATE: 'server',
                cls.CHANNEL_CODE_CLOSE: 'server',
                cls.CHANNEL_CODE_JOIN: 'server',
                cls.CHANNEL_CODE_PART: 'server'
            }
        }

    def __init__(self, key, slave_class, *args, **kwargs):
        """
        Instantiates a master broadcast by specifying a .
        """
        super(UserMasterBroadcast, self).__init__(key, slaves=List(slave_class), *args, **kwargs)

        def unregister_slave(list, instance, by_val):
            for ukey, user in instance.users():
                instance.force_part(user, special="slave-unregister", *args, **kwargs)

        def unregister_user(list, instance, by_val):
            for skey, slave in items(self.slaves):
                slave.force_part(instance, special="user-unregister", *args, **kwargs)
            del instance.socket.user_endpoint

        self.slaves.events.remove.register(unregister_slave)
        self.list.events.remove.register(unregister_user)

    def register(self, user, *args, **kwargs):
        """
        Creates a user (arguments are considered) on master lists.
        """
        return self.list.create(user, *args, **kwargs)

    def slave_register(self, key, *args, **kwargs):
        """
        Creates a slave, based on given arguments.
        """
        return self.slaves.create(key, self, *args, **kwargs)

    def slave_unregister(self, key, *args, **kwargs):
        """
        Destroys a slave, based on its arguments.
        """
        return self.slaves.remove(key)

    command_login = AccessControlledAction(
        lambda obj, socket, *args, **kwargs: obj._command_is_allowed_login(socket, *args, **kwargs),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket, *args, **kwargs: obj._command_accepted_login(result, socket, *args, **kwargs),
        lambda obj, result, socket, *args, **kwargs: obj._command_rejected_login(result, socket, *args, **kwargs),
    ).as_method("""
    Allows sockets to log-in to the server. Its check (_login_command_is_allowed) MUST be implemented.
    """)

    command_logout = AccessControlledAction(
        lambda obj, socket, *args, **kwargs: obj._command_is_allowed_logout(socket, *args, **kwargs),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket, *args, **kwargs: obj._command_accepted_logout(result, socket, *args, **kwargs),
        lambda obj, result, socket, *args, **kwargs: obj._command_rejected_logout(result, socket, *args, **kwargs),
    ).as_method("""
    Allows sockets to log-out from the server.
    """)

    command_create_slave = AccessControlledAction(
        lambda obj, user, slave_name, *args, **kwargs: obj._command_is_allowed_create_slave(user, slave_name, *args, **kwargs),
        lambda obj, result: obj.accepts(result),
        lambda obj, result, user, slave_name, *args, **kwargs: obj._command_accepted_create_slave(result, user, slave_name, *args, **kwargs),
        lambda obj, result, user, slave_name, *args, **kwargs: obj._command_rejected_create_slave(result, user, slave_name, *args, **kwargs)
    ).as_method("""
    Allows users to create slave broadcasts.
    """)

    command_close_slave = AccessControlledAction(
        lambda obj, user, slave_name, *args, **kwargs: obj._command_is_allowed_close_slave(user, slave_name, *args, **kwargs),
        lambda obj, result: obj.accepts(result),
        lambda obj, result, user, slave_name, *args, **kwargs: obj._command_accepted_close_slave(result, user, slave_name, *args, **kwargs),
        lambda obj, result, user, slave_name, *args, **kwargs: obj._command_rejected_close_slave(result, user, slave_name, *args, **kwargs)
    ).as_method("""
    Allows users to close/destroy broadcasts.
    """)

    def force_logout(self, user, *args, **kwargs):
        """
        Logs a user out, by key. The user will be notified. Since this
          command is not executed by the client, it must return a boolean
          value indicating whether the user was logged in or not.
        """
        if user in self._broadcast.users():
            self.unregister(self.users()[user], *args, **kwargs)
            user.socket.send_message(self.AUTHENTICATE_NS, self.AUTHENTICATE_CODE_FORCED_LOGOUT, *args, **kwargs)
            return True
        else:
            return False

    def _impl_login(self, socket, *args, **kwargs):
        """
        Performs log-in. Should return a triple:
          (user key, user args, user kwargs).
        """
        raise NotImplementedError

    def _command_is_allowed_create_slave(self, user, slave_name, *args, **kwargs):
        """
        States whether the user is allowed to create the slave.
        """
        return self._result_deny(self.CHANNEL_RESULT_DENY_CREATE)

    def _command_accepted_create_slave(self, result, user, slave_name, *args, **kwargs):
        """
        Handles when the slave creation succeeds.
        """
        self.notify(user, (self.CHANNEL_RESPONSE_NS, self.CHANNEL_RESPONSE_CODE_RESPONSE), result=result, channel=slave_name)
        self.slave_register(slave_name, *args, **kwargs)

    def _command_rejected_create_slave(self, result, user, slave_name, *args, **kwargs):
        """
        Handles when the slave creation fails.
        """
        self.notify(user, (self.CHANNEL_RESPONSE_NS, self.CHANNEL_RESPONSE_CODE_RESPONSE), result=result, channel=slave_name)

    def _command_is_allowed_close_slave(self, user, slave_name, *args, **kwargs):
        """
        States whether the user is allowed to close the slave.
        """
        return self._result_deny(self.CHANNEL_RESULT_DENY_CLOSE)

    def _command_accepted_close_slave(self, result, user, slave_name, *args, **kwargs):
        """
        Handles when the slave closure succeeds.
        """
        self.notify(user, (self.CHANNEL_RESPONSE_NS, self.CHANNEL_RESPONSE_CODE_RESPONSE), result=result, channel=slave_name)
        self.slave_unregister(slave_name, *args, **kwargs)

    def _command_rejected_close_slave(self, result, user, slave_name, *args, **kwargs):
        """
        Handles when the slave closure fails.
        """
        self.notify(user, (self.CHANNEL_RESPONSE_NS, self.CHANNEL_RESPONSE_CODE_RESPONSE), result=result, channel=slave_name)

    def _command_is_allowed_login(self, socket, *args, **kwargs):
        """
        Checks whether a user must be allowed, or not, to log-in (e.g. bad user/password).
        """
        user = getattr(socket, 'user_endpoint')
        if user and user in self.users():
            return self._result_deny(self.AUTHENTICATE_RESULT_DENY_ALREADY_ACTIVE_SESSION)
        else:
            return self._impl_login(socket, *args, **kwargs) or self._result_deny(self.AUTHENTICATE_RESULT_DENY_INVALID)

    def _command_accepted_login(self, result, socket, *args, **kwargs):
        """
        Accepts the login attempt and registers the user in the broadcast.
        """
        user_key, user_args, user_kwargs = result
        self.register(user_key, *user_args, **user_kwargs)
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)

    def _command_rejected_login(self, result, socket, *args, **kwargs):
        """
        Rejects the login attempt with the gotten result.
        """
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)

    def _command_is_allowed_logout(self, socket, *args, **kwargs):
        """
        Checks whether the socket should be allowed to logout.
        """
        user = getattr(socket, 'user_endpoint')
        if user and user in self.users():
            return self._result_allow(self.AUTHENTICATE_RESULT_ALLOW_LOGGED_OUT)
        else:
            return self._result_deny(self.AUTHENTICATE_RESULT_DENY_NO_ACTIVE_SESSION)

    def _command_accepted_logout(self, result, socket, *args, **kwargs):
        """
        Accepts the logout command and cleans the user_endpoint.
        """
        self.unregister(socket.user_endpoint, *args, **kwargs)
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)

    def _command_rejected_logout(self, result, socket, *args, **kwargs):
        """
        Rejects the logout command, and cleans the user_endpoint (perhaps an expired session exists).
        """
        if hasattr(socket, 'user_endpoint'):
            del socket.user_endpoint
        socket.send_message(self.AUTHENTICATE_RESPONSE_NS, self.AUTHENTICATE_RESPONSE_CODE_RESPONSE, result=result)
from base import UserBroadcast
from cantrips.patterns.actions import AccessControlledAction
from cantrips.protocol.traits.decorators.authcheck import IAuthCheck


class UserSlaveBroadcast(UserBroadcast, IAuthCheck):
    """
    This broadcast adds an existing user. It does not support login features.
    """

    def __init__(self, key, master, *args, **kwargs):
        super(UserSlaveBroadcast, self).__init__(key, master=master, *args, **kwargs)

    def auth_check(self, socket, state=True):
        """
        Delegates the auth check in the assigned-to master.
        """
        return self.master.auth_check(socket, state)

    def register(self, user, *args, **kwargs):
        """
        Inserts a user instance (arguments are ignored).
        """
        return self.list.insert(user)

    def force_part(self, user, *args, **kwargs):
        """
        Forces a user to be removed from the slave.
        """
        pass

    command_join = IAuthCheck.logout_required(AccessControlledAction(
        lambda obj, socket: obj._command_is_allowed_join(socket),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket: obj._command_accepted_join(result, socket),
        lambda obj, result, socket: obj._command_rejected_join(result, socket)
    ).as_method("""
    Lets a user join this slave.
    """))

    command_part = IAuthCheck.logout_required(AccessControlledAction(
        lambda obj, socket: obj._command_is_allowed_part(socket),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket: obj._command_accepted_part(result, socket),
        lambda obj, result, socket: obj._command_rejected_part(result, socket)
    ).as_method("""
    Lets a user leave this slave.
    """))

    def _command_is_allowed_join(self, socket):
        """

        """
        pass

    def _command_accepted_join(self, socket):
        """

        """
        pass

    def _command_rejected_join(self, socket):
        """

        """
        pass

    def _command_is_allowed_part(self, socket):
        """

        """
        pass

    def _command_accepted_part(self, socket):
        """

        """
        pass

    def _command_rejected_part(self, socket):
        """

        """
        pass
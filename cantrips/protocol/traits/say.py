from cantrips.patterns.actions import AccessControlledAction
from cantrips.patterns.broadcast import IBroadcast
from cantrips.protocol.traits.permcheck import PermCheck


class SayBroadcast(IBroadcast, PermCheck):

    SAY_NS = 'say'
    SAY_CODE_SAID = 'said'

    SAY_RESPONSE_NS = 'notify'
    SAY_RESPONSE_CODE_RESPONSE = 'response'

    SAY_RESULT_DENY_NOT_IN = 'not-in'
    SAY_RESULT_ALLOW = 'ok'

    say = AccessControlledAction(
        lambda obj, user, message: obj._say_command_is_allowed(user, message),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, user, message: obj._say_command_on_accepted(result, user, message),
        lambda obj, result, user, message: obj._say_command_on_rejected(result, user, message),
    ).as_method("""
    A user (given by key or instance) can send a message to the broadcast.
    This is restricted to users already subscribed to the broadcast.

    To customize the protocol for this command, refer and override each SAY_* class member.
    """)

    def _say_command_is_allowed(self, user, message):
        """
        Determines whether the user is allowed to send a message.

        Primitive check - allow only connected users.
        """
        if user not in self.users():
            return self._result_deny(self.SAY_RESULT_DENY_NOT_IN)
        return self._result_allow(self.SAY_RESULT_ALLOW)

    def _say_command_on_accepted(self, result, publisher, message):
        """
        User message was accepted. Notify the user AND broadcast the message to other users.
        """
        self.notify(publisher, (self.SAY_RESPONSE_NS, self.SAY_RESPONSE_CODE_RESPONSE), result=result, message=message)
        others = IBroadcast.BROADCAST_FILTER_OTHERS(self.users()[publisher])
        self.broadcast((self.SAY_NS, self.SAY_CODE_SAID), user=publisher, message=message, filter=others)

    def _say_command_on_rejected(self, result, publisher, message):
        """
        User message was rejected.
        """
        self.notify(publisher, (self.SAY_RESPONSE_NS, self.SAY_RESPONSE_CODE_RESPONSE), result=result, message=message)
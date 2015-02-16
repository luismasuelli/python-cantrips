from cantrips.patterns.actions import AccessControlledAction
from cantrips.patterns.broadcast import IBroadcast
from cantrips.protocol.traits.decorators.authcheck import IAuthCheck
from cantrips.protocol.traits.decorators.incheck import IInCheck
from cantrips.protocol.traits.permcheck import PermCheck
from cantrips.protocol.traits.provider import IProtocolProvider


class SayBroadcast(IBroadcast, PermCheck, IProtocolProvider, IAuthCheck, IInCheck):
    """
    This trait, applied to an existent broadcast, lets users
      to publish messages to the whole broadcast.
    """

    SAY_NS = 'say'
    SAY_CODE_SAID = 'said'

    SAY_RESPONSE_NS = 'notify'
    SAY_RESPONSE_CODE_RESPONSE = 'response'

    SAY_RESULT_ALLOW = 'ok'

    @classmethod
    def specification(cls):
        return {
            cls.SAY_NS: {
                cls.SAY_CODE_SAID: 'client'
            },
            cls.SAY_RESPONSE_NS: {
                cls.SAY_RESPONSE_CODE_RESPONSE: 'client'
            }
        }

    say = IInCheck.in_required(AccessControlledAction(
        lambda obj, socket, message: obj._say_command_is_allowed(socket, message),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, socket, message: obj._say_command_on_accepted(result, socket, message),
        lambda obj, result, socket, message: obj._say_command_on_rejected(result, socket, message),
    ).as_method("""
    A user (given by key or instance) can send a message to the broadcast.
    This is restricted to users already subscribed to the broadcast.

    To customize the protocol for this command, refer and override each SAY_* class member.
    """))

    def _say_command_is_allowed(self, socket, message):
        """
        Determines whether the user is allowed to send a message.

        Primitive check - allow only connected users.
        """
        return self._result_allow(self.SAY_RESULT_ALLOW)

    def _say_command_on_accepted(self, result, socket, message):
        """
        User message was accepted. Notify the user AND broadcast the message to other users.
        """
        socket.send_message(self.SAY_RESPONSE_NS, self.SAY_RESPONSE_CODE_RESPONSE, result=result, message=message)
        others = IBroadcast.BROADCAST_FILTER_OTHERS(self.users()[self.auth_get(socket)])
        self.broadcast((self.SAY_NS, self.SAY_CODE_SAID), user=self.auth_get(socket).key, message=message, filter=others)

    def _say_command_on_rejected(self, result, socket, message):
        """
        User message was rejected.
        """
        socket.send_message(self.SAY_RESPONSE_NS, self.SAY_RESPONSE_CODE_RESPONSE, result=result, message=message)
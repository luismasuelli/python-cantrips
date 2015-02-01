from cantrips.patterns.actions import AccessControlledAction
from cantrips.patterns.broadcast import IBroadcast
from cantrips.protocol.traits.permcheck import PermCheck


class WhisperBroadcast(IBroadcast, PermCheck):
    """
    This traits, applied to an existent broadcast, lets a
      user send a private message to another user. Both
      users must belong to the current broadcast.
    """

    WHISPER_NS = 'whisper'
    WHISPER_CODE_SAID = 'whispered'

    WHISPER_RESPONSE_NS = 'notify'
    WHISPER_RESPONSE_CODE_RESPONSE = 'response'

    WHISPER_RESULT_DENY_NOT_IN = 'not-in'
    WHISPER_RESULT_DENY_TARGET_NOT_IN = 'target-not-in'
    WHISPER_RESULT_ALLOW = 'ok'

    whisper = AccessControlledAction(
        lambda obj, user, message: obj._whisper_command_is_allowed(user, message),
        lambda obj, result: obj._accepts(result),
        lambda obj, result, user, message: obj._whisper_command_on_accepted(result, user, message),
        lambda obj, result, user, message: obj._whisper_command_on_rejected(result, user, message),
    ).as_method("""
    A user (given by key or instance) can send a message to another user in the broadcast.
    This is restricted to users already subscribed to the broadcast (both must belong).

    To customize the protocol for this command, refer and override each WHISPER_* class member.

    Target user should not be an instance but a key, unless the instance implements an appropiate
      serialization mechanism.
    """)

    def _whisper_command_is_allowed(self, user, target, message):
        """
        Determines whether the user is allowed to whisper a message to another user.

        Primitive check - allow only connected users (both user and target).
        """
        if user not in self.users():
            return self._result_deny(self.WHISPER_RESULT_DENY_NOT_IN)
        if target not in self.users():
            return self._result_deny(self.WHISPER_RESULT_DENY_TARGET_NOT_IN)
        return self._result_allow(self.WHISPER_RESULT_ALLOW)

    def _whisper_command_on_accepted(self, result, user, target, message):
        """
        User message was accepted. Notify the user AND broadcast the message to other users.
        """
        self.notify(user, (self.WHISPER_RESPONSE_NS, self.WHISPER_RESPONSE_CODE_RESPONSE), result=result, target=target, message=message)
        self.notify(target, (self.WHISPER_NS, self.WHISPER_CODE_SAID), sender=user, message=message)

    def _whisper_command_on_rejected(self, result, user, target, message):
        """
        User message was rejected.
        """
        self.notify(user, (self.WHISPER_RESPONSE_NS, self.WHISPER_RESPONSE_CODE_RESPONSE), result=result, target=target, message=message)
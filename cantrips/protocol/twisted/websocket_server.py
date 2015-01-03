try:
    from autobahn.twisted.websocket import WebSocketServerProtocol
except:
    raise ImportError("You need to install twisted "
                      "(pip install twisted==14.0.2), "
                      "AND Autobahn for Python "
                      "(pip install autobahn), "
                      "for this to work. As an alternative, "
                      "you can install both Autobahn and Twisted"
                      "by executing: pip install autobahn[twisted]")
import logging
import json
from cantrips.protocol.messaging import MessageNamespaceSet, Message
from future.utils import istext


logger = logging.getLogger("cantrips.protocol.autobahn")


class MessageProtocol(WebSocketServerProtocol):
    """
    This handler formats the messages using json. Messages
      must match a certain specification defined in the
      derivated classes.
    """

    def __init__(self, strict=False):
        """
        Initializes the protocol, stating whether, upon
          the invalid messages can be processed by the
          user or must be processed automatically.
        """

        self.strict = strict
        self._setup_ns()

    def _decode(self, payload, isBinary):
        try:
            return payload if isBinary else payload.decode('utf8')
        except UnicodeDecodeError:
            self.transport.loseConnection()

    @classmethod
    def _setup_ns(cls):
        if not hasattr(cls, '_ns_set'):
            cls._ns_set = MessageNamespaceSet(cls.setup())

    @classmethod
    def setup(cls):
        """
        Specifies the protocol messages to be delivered and
          received. This function must return a dictionary
          with key strings:
            { "name.space" : { "code": (direction), ... }, ... }

        Where direction may be:
          MessageFactory.DIRECTION_SERVER : this message can go to the server
          MessageFactory.DIRECTION_CLIENT : this message can go to the client
          MessageFactory.DIRECTION_BOTH : this message can go in both directions
        """

        return {}

    def packet_send(self, ns, code, *args, **kwargs):
        """
        Sends a packet with a namespace, a message code, and arbitrary
          arguments. Messages must be checked for their direction whether
          they can be sent to the client.
        """

        data = json.dumps(self._ns_set.find(ns).find(code).build_message(*args, **kwargs).serialize(True))
        self.transport.write(data, not istext(data))
        return True

    def packet_process(self, message):
        """
        Processes a message by running a specific behavior. If
          this function returns False, the connection is closed.
        """

        return True

    def packet_invalid(self, error):
        """
        Processes an exception by running certain behavior. It is
          the same as processing a normal message: If this function
          returns False, the connection is closed.
        """

        return False

    def packet_hello(self):
        """
        Processes an on-connection behavior. It is completely safe to
          send messages to the other endpoint.
        """

        pass

    def packet_goodbye(self):
        """
        Processes an on-disconnection behavior. It is completely safe to
          send messages to the other endpoint, since the closing reason is
          not the client already closed the connection, but a protocol error
          or an agreed connection-close command.
        """

        pass

    def onOpen(self):
        try:
            self.packet_hello()
        except Message.Error as e:
            self._close_protocol_violation(e.parts)
        except Exception as e:
            self._close_unknown(e)

    def onMessage(self, payload, isBinary):
        payload = self._decode(payload, isBinary)
        try:
            self._close_unless(self.packet_process(self._ns_set.unserialize(json.loads(payload), True)))
        except (ValueError, Message.Error) as error:
            if self.strict:
                if isinstance(error, Message.Error):
                    if getattr(error, 'code', False) == "messaging:message:invalid":
                        self._close_invalid_format(error.parts)
                    else:
                        self._close_protocol_violation(error.parts)
                else:
                    self._close_invalid_format(error.value)
            else:
                self._close_unless(self.packet_invalid(error))
        except Exception as error:
            if self.strict:
                self._close_unknown(error)
            else:
                self._close_unless(self.packet_invalid(error))

    def _close_invalid_format(self, parts):
        logger.debug("Message format error for: " + repr(parts))
        #Cuando se apruebe el draft, 1003 sera usado para el formato de los datos.
        self.failConnection(3003, "Message format error")

    def _close_protocol_violation(self, parts):
        logger.debug("Unexistent or unavailable message: " + repr(parts))
        #Cuando se apruebe el draft, 1002 sera para mensaje no disponible o violacion de protocolo
        self.failConnection(3002, "Unexistent or unavailable message")

    def _close_unknown(self, exception):
        logger.debug("Cannot fullfill request: Exception triggered: %s - %s" % (type(exception).__name__, str(exception)))
        #Cuando se apruebe el draft, 1011 sera para notificar que la peticion no pudo realizarse
        self.failConnection(3011, "Cannot fullfill request: Internal server error")

    def _close_unless(self, result):
        if not result:
            try:
                self.packet_goodbye()
            except Message.Error as e:
                self._close_protocol_violation(e.parts)
            except Exception as e:
                self._close_unknown(e)
            self.failConnection(1000)
try:
    from tornado.websocket import WebSocketHandler
except:
    raise ImportError("You need to install tornado for this to work (pip install tornado==4.0.2)")
import logging
import json
from cantrips.protocol.messaging import MessageNamespaceSet, Message


logger = logging.getLogger("cantrips.protocol.tornado")


class WSMessageHandler(WebSocketHandler):
    """
    This handler formats the messages using json. Messages
      must match a certain specification defined in the
      derivated classes.
    """

    def initialize(self, strict=False):
        """
        Initializes the handler by specifying whether the
          error processing will be automatic (strict=True)
          or the user will be able to handle the error
          processing.
        """

        self.strict = strict
        self._setup_ns()

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

        self.write_message(json.dumps(self._ns_set.find(ns).find(code).build_message(*args, **kwargs).serialize(True)))
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

    def open(self):
        try:
            self.packet_hello()
        except Message.Error as e:
            self._close_protocol_violation(e.parts)
        except Exception as e:
            self._close_unknown(e)

    def on_message(self, message):
        try:
            self._close_unless(self.packet_process(self._ns_set.unserialize(json.loads(message), True)))
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
        self.close(3003, "Message format error")

    def _close_protocol_violation(self, parts):
        logger.debug("Unexistent or unavailable message: " + repr(parts))
        #Cuando se apruebe el draft, 1002 sera para mensaje no disponible o violacion de protocolo
        self.close(3002, "Unexistent or unavailable message")

    def _close_unknown(self, exception):
        logger.debug("Cannot fullfill request: Exception triggered: %s - %s" % (type(exception).__name__, str(exception)))
        #Cuando se apruebe el draft, 1011 sera para notificar que la peticion no pudo realizarse
        self.close(3011, "Cannot fullfill request: Internal server error")

    def _close_unless(self, result):
        if not result:
            try:
                self.packet_goodbye()
            except Message.Error as e:
                self._close_protocol_violation(e.parts)
            except Exception as e:
                self._close_unknown(e)
            self.close(1000)
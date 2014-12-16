from .packet import Packet
from ..exception import factory


class Message(Packet):
    """
    A message is a packet with a namespace and a command.
    Both values, when compound, build the `code` property.
    """

    Error = factory({
        'CANNOT_SERIALIZE_NONCLIENT_MESSAGE': 1,
        'CANNOT_UNSERIALIZE_NONSERVER_MESSAGE': 2,
        'FACTORY_ALREADY_EXISTS': 3,
        'FACTORY_DOES_NOT_EXIST': 4,
        'NAMESPACE_ALREADY_EXISTS': 5,
        'NAMESPACE_DOES_NOT_EXIST': 6,
        'INVALID_FORMAT': 7
    })

    def __init__(self, namespace, command, *args, **kwargs):
        super(Message, self).__init__("%s.%s" % (namespace, command), *args, **kwargs)

    def serialize(self, expect_clientwise=False):
        parts = {
            "code": self.code,
            "args": self.args,
            "kwargs": self.kwargs
        }

        if expect_clientwise and not (self.direction & MessageFactory.DIRECTION_CLIENT):
            raise Message.Error("Message cannot be serialized since it's not client-wise",
                                Message.Error.CANNOT_SERIALIZE_NONCLIENT_MESSAGE,
                                parts=parts)
        else:
            return parts


class MessageFactory(object):
    """
    A message factory builds messages from a code and namespace.
    """

    DIRECTION_CLIENT = 1
    DIRECTION_SERVER = 2
    DIRECTION_BOTH = 3

    def __init__(self, namespace, code, direction):
        self.__namespace = namespace
        self.__code = code
        self.__direction = direction

    def build(self, *args, **kwargs):
        return Message(self.namespace.code, self.code, *args, **kwargs)

    @property
    def code(self):
        return self.__code

    @property
    def namespace(self):
        return self.__namespace

    @property
    def direction(self):
        return self.__direction


class MessageNamespace(object):
    """
    A message namespace creates/registers commands.
    """

    def __init__(self, code):
        self.__code = code
        self.__messages = {}

    @property
    def code(self):
        return self.__code

    def register(self, code, direction, silent=False):
        try:
            x = self.__messages[code]
            if silent:
                return x
            else:
                raise Message.Error("Factory with that code already exists",
                                    Message.Error.FACTORY_ALREADY_EXISTS,
                                    factory_code=code)
        except KeyError:
            x = MessageFactory(self.code, code, direction)
            self.__messages[code] = x
            return x

    def find(self, code):
        try:
            return self.__messages[code]
        except KeyError:
            raise Message.Error("Message not registered",
                                Message.Error.FACTORY_DOES_NOT_EXIST,
                                factory_code=code)


class MessageNamespaceSet(object):
    """
    A message namespace set creates/registers message namespaces.
    """

    def __init__(self, namespaces):
        self.__namespaces = {}
        x = self.register("messaging")
        x.register("error", MessageFactory.DIRECTION_CLIENT)

        opts = {
            "server": MessageFactory.DIRECTION_SERVER,
            "client": MessageFactory.DIRECTION_CLIENT,
            "both": MessageFactory.DIRECTION_BOTH
        }
        for k, v in namespaces.iteritems():
            x = self.register(k, True)
            for k2, d in v.iteritems():
                x.register(k2, opts[d.lower()], True)

    def register(self, code, silent=False):
        try:
            x = self.__namespaces[code]
            if silent:
                return x
            else:
                raise Message.Error("Message namespace already registered",
                                    Message.Error.NAMESPACE_ALREADY_EXISTS,
                                    namespace_code=code)
        except KeyError:
            x = MessageNamespace(code)
            self.__namespaces[code] = x
            return x

    def find(self, code):
        try:
            return self.__namespaces[code]
        except KeyError:
            raise Message.Error("Message namespace not registered",
                                Message.Error.NAMESPACE_DOES_NOT_EXIST,
                                namespace_code=code)

    def unserialize(self, obj, expect_serverwise=False):
        if not isinstance(obj['code'], basestring) or not isinstance(obj['args'], list) or not isinstance(obj['kwargs'], dict):
            raise Message.Error("Expected format message is {code:string, args:list, kwargs:dict}",
                                Message.Error.INVALID_FORMAT,
                                parts=obj)
        else:
            code_parts = obj['code'].rsplit(".", 1)
            if len(code_parts) != 2:
                raise Message.Error("Message code must be in format `namespace.code`. Current: " + obj.code,
                                    Message.Error.INVALID_FORMAT,
                                    parts=obj)
            else:
                factory = self.find(code_parts[0]).find(code_parts[1])
                if expect_serverwise and not (factory.direction & MessageFactory.DIRECTION_SERVER):
                    raise Message.Error("Message cannot be unserialized since it's not server-wise",
                                        Message.Error.CANNOT_UNSERIALIZE_NONSERVER_MESSAGE,
                                        parts=obj)
                return factory.build(*obj['args'], **obj['kwargs'])
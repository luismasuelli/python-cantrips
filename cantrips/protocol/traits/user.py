from cantrips.patterns.broadcast import IBroadcast
from cantrips.patterns.identify import Identified, List


class UserEndpoint(Identified):
    """
    Base behavior for users. It bounds to a cantrips.protocol.messaging.MessageProcessor
      instance (socket), and "notifies" through it.
    """

    def __init__(self, key, socket, *args, **kwargs):
        socket.user_endpoint = self
        super(UserEndpoint, self).__init__(key, socket=socket, *args, **kwargs)

    def notify(self, ns, code, *args, **kwargs):
        return self.socket.send_message(ns, code, *args, **kwargs)


class UserEndpointList(List):
    """
    Endpoint list. It can specify the class to be used as endpoint.
    """

    @classmethod
    def endpoint_class(cls):
        """
        Class to be used as endpoint class.
        """
        return UserEndpoint

    def __init__(self):
        super(UserEndpointList, self).__init__(self.endpoint_class())


class UserBroadcast(Identified, IBroadcast):
    """
    Broadcast implementation for such endpoint list. Implements registration
      by using an endpoint list (the endpoint list may be custom-instantiated
      by descending classes).

    If instantiated with master=True (default), it creates users (i.e. accepts key and
      additional arguments), otherwise it can only add users (additional arguments are
      inserted, and the first argument must be an already-created instance) which are
      already-created instances.
    """

    @classmethod
    def endpoint_list_class(cls):
        """
        Class to be used as endpoint list class.
        """
        return UserEndpointList

    @classmethod
    def _endpoint_list(cls):
        """
        Instantiates an endpoint list.
        """
        return cls.endpoint_list_class()()

    def __init__(self, key, master=True):
        super(UserBroadcast, self).__init__(key, master=master, list=self._endpoint_list())
        self.list.events.insert.register(self._on_register)
        self.list.events.remove.register(self._on_unregister)

    def users(self):
        """
        Users list.
        """
        return self.list

    def _on_register(self, list, instance):
        """
        A user was inserted (or created). `instance` is passed by keyword - `instance.key`
          is the user id.
        """
        pass

    def _on_unregister(self, list, instance, by_val):
        """
        A user was removed. `instance` is passed by keyword - `instance.key` is the user id.
        """
        pass

    def register(self, user, *args, **kwargs):
        """
        Inserts a user instance (arguments are ignored) on non-master lists.
        Creates a user (arguments are considered) on master lists.
        """
        return self.list.create(user, *args, **kwargs) if self.master else self.list.insert(user)

    def unregister(self, user, *args, **kwargs):
        """
        Removes (unregisters) a user (it may be either key or instance).
          More args may be supplied for overriding implementations.
        """
        return self.list.remove(user)

    def notify(self, user, command, *args, **kwargs):
        """
        Sends a notification to a user.
          The command must be a tuple (ns, code).
          The user must be a key or the corresponding instance.
          More args may be supplied for the commands or overriding implementations.
        """
        ns, code = command
        return self.list[user].notify(ns, code, *args, **kwargs)
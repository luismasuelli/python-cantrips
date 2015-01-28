from cantrips.iteration import items


class INotifier(object):
    """
    Offers behavior to notify a user.
    """

    def notify(self, user, command, *args, **kwargs):
        """
        Notifies a user with a specified command/data.
        """

        raise NotImplementedError


class IRegistrar(object):
    """
    Offers behavior to register and unregister users.
    """

    def register(self, user, *args, **kwargs):
        """
        Registers a user.
        """

        raise NotImplementedError

    def unregister(self, user, *args, **kwargs):
        """
        Unregisters a user.
        """

        raise NotImplementedError

    def users(self):
        """
        Gets the list of users.
        """

        raise NotImplementedError


class IBroadcast(INotifier, IRegistrar):
    """
    Offers behavior to notify each user.
    """

    BROADCAST_FILTER_ALL = lambda user, command, *args, **kwargs: None

    def broadcast(self, command, *args, **kwargs):
        """
        Notifies each user with a specified command.
        """
        criterion = kwargs.pop('criterion', self.BROADCAST_FILTER_ALL)
        for index, user in items(self.users()):
            if criterion(user, command, *args, **kwargs):
                self.notify(user, command, *args, **kwargs)
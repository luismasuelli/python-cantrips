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

    @staticmethod
    def BROADCAST_FILTER_ALL(user, command, *args, **kwargs):
        """
        FIRST-ORDER (pass it as IBroadcast.BROADCAST_FILTER_ALL)
        Criteria to broadcast to every user
        """
        return True

    @staticmethod
    def BROADCAST_FILTER_OTHERS(user):
        """
        HIGH-ORDER (pass it as IBroadcast.BROADCAST_FILTER_OTHERS(user-or-sequence))
        Criteria to broadcast to every user but the current(s).
        """
        if not isinstance(user, (set,frozenset,list,tuple)):
            user = (user,)
        return lambda u, command, *args, **kwargs: u not in user

    @staticmethod
    def BROADCAST_FILTER_AND(*funcs):
        """
        Composes the passed filters into an and-joined filter.
        """
        return lambda u, command, *args, **kwargs: all(f(u, command, *args, **kwargs) for f in funcs)

    @staticmethod
    def BROADCAST_FILTER_OR(*funcs):
        """
        Composes the passed filters into an and-joined filter.
        """
        return lambda u, command, *args, **kwargs: any(f(u, command, *args, **kwargs) for f in funcs)

    @staticmethod
    def BROADCAST_FILTER_NOT(func):
        """
        Composes the passed filters into an and-joined filter.
        """
        return lambda u, command, *args, **kwargs: not func(u, command, *args, **kwargs)

    def broadcast(self, command, *args, **kwargs):
        """
        Notifies each user with a specified command.
        """
        criterion = kwargs.pop('criterion', self.BROADCAST_FILTER_ALL)
        for index, user in items(self.users()):
            if criterion(user, command, *args, **kwargs):
                self.notify(user, command, *args, **kwargs)
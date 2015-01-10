class IEmitter(object):
    """
    This interface takes the task of sending notifications to all
      of its subscribers. This is done by calling notify() on each
      of the -subscribed- ISubscriber instances.
    """

    def subscribers(self):
        """
        Returns a dict-iterator for the current broadcast's subscribers.
        This dict-iterator is an `iteritems`-like iterator.
        """
        raise NotImplementedError

    def notify(self, code, condition=lambda key, value: True, *args, **kwargs):
        """
        For each subscriber, notifies it with the current arguments.
        Passes code, *args, **kwargs to the per-user notification.
        Uses `condition` as a predicate to be evaluated on each user.
        Users for which the predicate returns a False-like value
          are not notified.
        """
        for k, v in self.subscribers():
            if condition(k, v):
                v.notify(code, *args, **kwargs)


class ISubscriber(object):
    """
    This interface provides the .notify() method which will be used by
    the IEmitter interface.
    """

    def notify(self, code, *args, **kwargs):
        """
        This method should notify the instance by passing adequate arguments.
        Implementation is completely up-to-the-user.
        """
        raise NotImplementedError
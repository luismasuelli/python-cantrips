# coding=utf-8
from .exception import factory


class Eventful(object):
    """
    A bunch of events we could make use of.
    We can be explicit on declaring the events, and/or we can
        let the user declare them on-the-fly (by passing
        strict=False).
    """

    Error = factory({'INVALID_EVENT': 1})

    class Event(object):
        """
        Maps each handler as id => handler.
        Lets the user register and unregister handlers.
        Lets the user trigger the current bunch of handlers.
        """

        Error = factory({'HANDLER_KEY_IN_USE': 1, 'HANDLER_KEY_NOT_IN_USE': 2})

        def __init__(self):
            self.__handlers = {}

        def trigger(self, *args, **kwargs):
            """
            Runs each handler sequentially.
            Altering the handlers will not have effect until
                the current call to this method ends.
            """
            for key, handler in self.__handlers.copy().iteritems():
                handler(*args, **kwargs)

        def register(self, key, handler):
            """
            Registers an event handler for this event.
            """
            if key in self.__handlers:
                raise self.Error("Event handler key in use: %s" % key, self.Error.HANDLER_KEY_IN_USE, key=key)
            self.__handlers[key] = handler

        def unregister(self, key):
            """
            Unregisters an event handler for this event.
            """
            if key not in self.__handlers:
                raise self.Error("Event handler key not in use: %s" % key, self.Error.HANDLER_KEY_NOT_IN_USE, key=key)
            del self.__handlers[key]

    def __init__(self, events=(), strict=True):
        """
        Event names become attributes of this object.
        Pass strict=False to allow the user to declare
            new events on the fly.
        """
        self.__strict = strict
        [setattr(self, event, self.Event()) for event in set(events)]

    def __getattr__(self, item):
        """
        Since no attribute was matched, in strict mode
            an AttributeError will be raised. However
            in non-strict error no exception will be
            raised. Instead, a new Event object will
            be created, set as attribute, and returned.
        """
        if self.__strict:
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, item))
        ev = self.Event()
        setattr(self, item, ev)
        return ev
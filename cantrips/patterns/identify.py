from cantrips.types.arguments import Arguments
from cantrips.types.exception import factory
from cantrips.types.events import Eventful
from future.utils import PY3


class Identified(Arguments):
    """
    Each of these objects has a key.
    """

    def __init__(self, key, *args, **kwargs):
        super(Identified, self).__init__(key=key, *args, **kwargs)


class List(object):
    """
    Keeps a list of identified objects by key. A key cannot be registered twice.
    It can track when objects are created, inserted, and removed from it.
    """

    Error = factory(['INVALID_CLASS', 'INVALID_INSTANCE_CLASS', 'KEY_EXISTS', 'KEY_NOT_EXISTS', 'NOT_SAME_OBJECT'])

    def __init__(self, element_class=Identified):
        if not issubclass(element_class, Identified):
            raise self.Error("class '%s' is not a valid Identified subclass" % element_class.__name__,
                             self.Error.INVALID_CLASS, element_class=element_class)
        self._class = element_class
        self._objects = {}
        self._events = Eventful(('create', 'insert', 'remove'))

    @property
    def events(self):
        """
        Returns the available events for the current list.
        Events are limited to:
            create: when an instance is created (but not yet inserted)
                    by the `create(key, *args, **kwargs)` method.
                    Triggered passing the current list, the instance,
                    the key, and the remaining arguments.
            insert: when an instance is inserted by the
                    `insert(instance)` method.
                    Triggered passing the current list, and the instance.
            remove: when an instance is removed by the
                    `remove(instance|key)` method.
                    Triggered passing the current list, the instance, and
                    indicating whether it was by value or not (not=it was
                    by key).
        """

        return self._events

    def create(self, key, *args, **kwargs):
        """
        Creates and inserts an identified object with the passed params
            using the specified class.
        """
        instance = self._class(key, *args, **kwargs)
        self._events.create.trigger(list=self, instance=instance, key=key, args=args, kwargs=kwargs)
        return self.insert(instance)

    def insert(self, identified):
        """
        Inserts an already-created identified object of the expected class.
        """

        if not isinstance(identified, self._class):
            raise self.Error("Passed instance is not of the needed class",
                             self.Error.INVALID_INSTANCE_CLASS, instance=identified)

        try:
            if self._objects[identified.key] != identified:
                raise self.Error("Passes instance's key '%s' is already occupied" % identified.key,
                                 self.Error.KEY_EXISTS, key=identified.key, instance=identified)
        except KeyError:
            self._objects[identified.key] = identified
            self._events.insert.trigger(list=self, instance=identified)
        return identified

    def remove(self, identified):
        """
        Removes an already-created identified object.
        A key may be passed instead of an identified object.
        If an object is passed, and its key is held by another
            object inside the record, an error is triggered.
        Returns the removed object.
        """

        by_val = isinstance(identified, Identified)
        if by_val:
            key = identified.key
            if not isinstance(identified, self._class):
                raise self.Error("Such instance could never exist here",
                                 self.Error.INVALID_INSTANCE_CLASS, instance=identified)
        else:
            key = identified

        try:
            popped = self._objects.pop(key)
            if by_val and popped != identified:
                raise self.Error("Trying to pop a different object which also has key '%s'" % popped.key,
                                 self.Error.NOT_SAME_OBJECT, instance=identified, current=popped)
            self._events.remove.trigger(list=self, instance=identified, by_val=by_val)
        except KeyError:
            raise self.Error("No object with key '%s' exists here",
                             self.Error.KEY_NOT_EXISTS, key=key, instance=identified if by_val else None)

    def items(self):
        """
        Gives a list -or iterator, in PY3- of inner items
        """
        return self._objects.items()

    if not PY3:

        def iteritems(self):
            """
            Gives an interator of inner items. This method is
              only available in Python 2.x
            """
            return self._objects.iteritems()

    def __iter__(self):
        """
        You can iterate over contained objects.
        """

        return iter(self._objects)

    def __len__(self):
        """
        length of the list, in items.
        """

        return len(self._objects)

    def __getitem__(self, item):
        """
        Returns a registered item by key (or the item itself, if it is an existent instance).
        """

        if isinstance(item, Identified):
            obj = self._objects[item.key]
            if obj is not item:
                raise KeyError(item)
            return obj
        else:
            return self._objects[item]

    def __contains__(self, item):
        """
        Determines whether an identified object OR a key is registered.
        """

        if isinstance(item, Identified):
            if not isinstance(item, self._class):
                return False
            return item.key in self._objects and self._objects[item.key] is item
        else:
            return item in self._objects
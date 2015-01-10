class TrackableRecord(object):
    """
    Can hold a set of changeable attributes. Attributes not
      initialized beforehand are NOT setable.
    Can also track the changes of the attributes.
    """

    def __init__(self, **kwargs):
        self.__dict = kwargs
        self.__tracking = False
        self.__changes = {}

    def __setattr__(self, key, value):
        """
        Allows to edit attribute only belonging to the
          initial attributes (it is like a per-object
          __slots__), and tracks the changes of the
          current instance's attributes if tracking
          is enabled.
        """
        if not key in self.__dict:
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, key))
        old = self.__dict[key]
        self.__dict[key] = value
        if self.__tracking:
            self.__changes.setdefault(key, {'old': old}).update({'new': value})

    def track_start(self):
        """
        Begins tracking of attributes changes.
        """
        self.__tracking = True

    def track_end(self):
        """
        Ends tracking of attributes changes.
        Returns the changes that occurred to the attributes.
          Only the final state of each attribute is obtained
        """
        self.__tracking = False
        changes = self.__changes
        self.__changes = {}
        return changes
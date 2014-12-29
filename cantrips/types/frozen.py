_dict = dict


class frozendict(_dict):
    """
    Implementation stolen from: http://code.activestate.com/recipes/414283/.
    It denies the modification of the current dictionary. I would
    """

    def _blocked_attribute(self):
        raise TypeError("'%s' object does not support modification" % type(self).__name__)
    _blocked_attribute = property(_blocked_attribute)

    __delitem__ = __setitem__ = clear = _blocked_attribute
    pop = popitem = setdefault = update = _blocked_attribute

    def __new__(cls, *args, **kwargs):
        new = _dict.__new__(cls)
        _dict.__init__(new, *args, **kwargs)
        return new

    def __init__(self, *args, **kwargs):
        pass

    def __hash__(self):
        try:
            return self._cached_hash
        except AttributeError:
            h = self._cached_hash = hash(frozenset(sorted(self.items())))
            return h

    def __repr__(self):
        return "frozendict(%s)" % _dict.__repr__(self)


list = tuple
set = frozenset
dict = frozendict
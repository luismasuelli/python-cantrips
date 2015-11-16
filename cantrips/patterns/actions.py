class Action(object):
    """
    This class can define a custom behavior, and then be exposed as a
      method. It doesn't matter if such method is instance or class method.

    This is intended to become a sort of "configurable method".
    """

    def __call__(self, obj, *args, **kwargs):
        raise NotImplementedError

    def as_method(self, docstring=""):
        """
        Converts this action to a function or method.
          An optional docstring may be passed.
        """
        method = lambda obj, *args, **kwargs: self(obj, *args, **kwargs)
        if docstring:
            method.__doc__ = docstring
        return method
class Action(object):
    """
    This class can define a custom behavior, and then be exposed as a
      method. It doesn't matter if such method is instance or class method.

    This is intended to become a sort of "configurable method".
    """

    def __call__(self, obj, *args, **kwargs):
        raise NotImplementedError

    def as_method(self):
        return lambda obj, *args, **kwargs: self(obj, *args, **kwargs)


class AccessControlledAction(Action):
    """
    This class can define an access-controlled action. This means that
      the output method executes a check and two possible actions:
      > is_allowed?:
      >   on_allowed
      > no?
      >   on_denied

    The three behaviors must be provided by constructor. The first
      behavior MUST return a boolean value. The other behaviors are
      not needed to return any special value or required type.
    """

    def __init__(self, is_allowed=lambda *args, **kwargs: True, on_allowed=lambda *args, **kwargs: True,
                 on_denied=lambda *args, **kwargs: False):
        self.is_allowed = is_allowed
        self.on_allowed = on_allowed
        self.on_denied = on_denied

    def __call__(self, *args, **kwargs):
        if self.is_allowed(*args, **kwargs):
            return self.on_allowed(*args, **kwargs)
        else:
            return self.on_denied(*args, **kwargs)

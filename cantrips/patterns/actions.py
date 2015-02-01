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


class AccessControlledAction(Action):
    """
    This class can define an access-controlled action. This means that
      the output method executes a check and two possible actions:
      > is_allowed?:
      >   on_allowed
      > no?
      >   on_denied

    This is composed by four behaviors.

    * The first behavior checks whether the call can be performed with the
      current arguments. It must return a kind of result which must tell,
      somehow, whether the operation should be accepted or not.
      Signature: your choice (will be considered as self, *args, **kwargs) => your choice.
    * The second behavior takes the result from the first behavior and
      should analyze it and tell whether such result is an "allowed" or a
      "denied" result. It is a complement for the first behavior.
      Signature: (self, result) => your choice.
      Notes: The returned value should be bool-evaluable.
    * The third behavior is the implementation of the "accepted" behavior.
      Signature: (self, result, *args, **kwargs).
      Notes: The *args and **kwargs are the same of the first behavior, so the
      signature should be based on it.
    * The fourth behavior is the implementation of the "rejected" behavior.
      Signature: the same for the accepted behavior.
      Notes: The same for the accepted behavior.
    """

    def __init__(self, check_allowed=lambda obj, *args, **kwargs: True, accepts=lambda obj, result: result,
                 on_allowed=lambda obj, result, *args, **kwargs: True, on_denied=lambda obj, result, *args, **kwargs: False):
        self.check_allowed = check_allowed
        self.accepts = accepts
        self.on_allowed = on_allowed
        self.on_denied = on_denied

    def __call__(self, obj, *args, **kwargs):
        result = self.check_allowed(obj, *args, **kwargs)
        if self.accepts(obj, result):
            return self.on_allowed(obj, result, *args, **kwargs)
        else:
            return self.on_denied(obj, result, *args, **kwargs)

from __future__ import absolute_import
import types

METHOD_CLASS = 1
METHOD_INSTANCE = 2
METHOD_BOUND = 4
METHOD_UNBOUND = 8
METHOD_ALL = METHOD_CLASS | METHOD_INSTANCE | METHOD_BOUND | METHOD_UNBOUND


def is_method(method, flags=METHOD_ALL):
    """
    Determines whether the passed value is a method satisfying certain conditions:
      * Being instance method.
      * Being class method.
      * Being bound method.
      * Being unbound method.
    Flag check is considered or-wise. The default is to consider every option.
    :param method:
    :param flags:
    :return:
    """
    if isinstance(method, types.UnboundMethodType):
        if flags & METHOD_CLASS and issubclass(method.im_class, type):
            return True
        if flags & METHOD_INSTANCE and not issubclass(method.im_class, type):
            return True
        if flags & METHOD_BOUND and method.im_self is not None:
            return True
        if flags & METHOD_UNBOUND and method.im_self is None:
            return True
    return False


def is_static(method):
    """
    Determines whether the passed value is a function (NOT a method).
    :param method:
    :return:
    """
    return isinstance(method, types.FunctionType)


is_function = is_static
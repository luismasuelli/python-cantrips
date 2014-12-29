from cantrips.types.arguments import Arguments


class _Exception(Arguments, Exception):

    def __init__(self, message, code, *args, **kwargs):
        Arguments.__init__(self, message=message, code=code, *args, **kwargs)
        Exception.__init__(self, message)


def factory(codes, base=_Exception):
    """
    Creates a custom exception class with arbitrary error codes and arguments.
    """

    if not issubclass(base, _Exception):
        raise FactoryException("Invalid class passed as parent: Must be a subclass of an Exception class created with this function",
                               FactoryException.INVALID_EXCEPTION_CLASS, intended_parent=base)

    class Error(base):
        pass

    if not isinstance(codes, dict):
        raise FactoryException("Factory codes must be a dict str -> object",
                               FactoryException.INVALID_CODES_LIST, intended_codes=codes)

    if not isinstance(codes, dict):
        codes = {v: v for v in codes}

    for code, value in codes.items():
        try:
            setattr(Error, code, value)
        except TypeError:
            raise FactoryException("Cannot set class attribute: (%r) -> (%r)" % (code, value),
                                   FactoryException.INVALID_CODE_VALUE, attribute=code, value=value)

    return Error


FactoryException = factory({'INVALID_EXCEPTION_CLASS': 1,
                            'INVALID_CODES_LIST': 2,
                            'INVALID_CODE_VALUE': 3})
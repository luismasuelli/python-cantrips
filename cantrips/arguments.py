from future.utils import python_2_unicode_compatible
from .frozen import dict


@python_2_unicode_compatible
class Arguments(object):
    """
    Takes any set of arguments into an object.
    This could be used as mixin to record any set of passed parameters to
        the current object.
    """

    def __init__(self, *args, **kwargs):
        """
        You can specify any set of arguments.

        Please consider that names like 'args' and 'kwargs' are
            occupied by special property names. If you use them,
            you must retrieve them as:

            o.kwargs['args']
            o.kwargs['kwargs']
        """
        super(Arguments, self).__setattr__('_Arguments__args', args)
        super(Arguments, self).__setattr__('_Arguments__kwargs', dict(**kwargs))

    def __len__(self):
        """
        Resolves length as the count of assigned arguments.
        """
        return len(self.__args) + len(self.__kwargs)

    def __add__(self, other):
        """
        Adds this set of parameters to another set of parameters.
        Returns the added set.
        """
        if not isinstance(other, type(self)):
            raise TypeError("unsupported operand type(s) for +: '%s' and '%s'" % (type(self).__name__, type(other).__name__))
        kwargs = self.__kwargs.copy()
        kwargs.update(other.__kwargs)
        args = self.__args + other.__args
        return Arguments(*args, **kwargs)

    def __contains__(self, item):
        """
        Resolves whether an argument (position or kw) was passed.
        """
        if isinstance(item, str):
            return item in self.__kwargs
        return 0 <= item < len(self.__args)

    def __getitem__(self, item):
        """
        Resolves an item by positional argument.
        """
        try:
            return self.__args[item]
        except IndexError:
            raise IndexError("argument index out of range")
        except TypeError:
            raise TypeError("argument indices must be integers, not %s" % type(item).__name__)
        except Exception:
            raise

    def __setitem__(self, key, value):
        """
        Fails when assigning item since it is inmutable.
        """
        raise TypeError("'%s' object does not support item assignment" % type(self).__name__)

    def __getattr__(self, item):
        """
        Resolves an attribute by keyword argument.
        """
        try:
            return self.__kwargs[item]
        except KeyError as e:
            raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, e.args[0]))

    def __setattr__(self, key, value):
        """
        Fails when assigning attribute since it is inmutable.
        """
        raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, key))

    def __str__(self):
        """
        String representation (will be unicode representation in python 2).
        """
        return str((self.__args, self.__kwargs))

    def __bytes__(self):
        """
        Bytes representation (will be str representation in python 2)
        """
        return bytes((self.__args, self.__kwargs))

    def __repr__(self):
        """
        Code representation.
        """
        return "%s(*%r,**%r)" % (type(self).__name__, self.__args, self.__kwargs)

    @property
    def args(self):
        """
        Copy of positional arguments.
        """
        return self.__args

    @property
    def kwargs(self):
        """
        Copy of keyword arguments.
        """
        return self.__kwargs
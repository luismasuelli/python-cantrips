import operator

try:
    from itertools import izip
except ImportError:
    izip = zip


def items(iterable):
    """
    Iterates over the items of a sequence. If the sequence supports the
      dictionary protocol (iteritems/items) then we use that. Otherwise
      we use the enumerate built-in function.
    """
    if hasattr(iterable, 'iteritems'):
        return (p for p in iterable.iteritems())
    elif hasattr(iterable, 'items'):
        return (p for p in iterable.items())
    else:
        return (p for p in enumerate(iterable))


def iterable(value):
    """
    If the value is not iterable, we convert it to an iterable containing
      that only value.
    :param x:
    :return:
    """
    try:
        return iter(value)
    except TypeError:
        return value,


try:
    from itertools import accumulate
except ImportError:
    def accumulate(p, func=operator.add):
        """
        Python3's itertools accumulate being ported to PY2
        :param p:
        :param func:
        :return:
        """
        iterator = iter(p)
        current = next(iterator)
        for k in iterator:
            yield current
            current = func(current, k)
        yield current


def labeled_accumulate(sequence, keygetter=operator.itemgetter(0), valuegetter=operator.itemgetter(1), accumulator=operator.add):
    """
    Accumulates input elements according to accumulate(), but keeping certain data (per element, from the original
      sequence/iterable) in the target elements, like behaving as keys or legends.
    :param sequence:
    :param keygetter:
    :param valuegetter:
    :return:
    """
    return izip((keygetter(item) for item in sequence),
                accumulate((valuegetter(item) for item in sequence), accumulator))
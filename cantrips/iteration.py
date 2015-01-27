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
from collections import namedtuple


def can_take(attrs_to_freeze=(), defaults=None, source_attr='source', instance_property_name='snapshot', inner_class_name='Snapshot'):
    """
    Decorator to make a class allow their instances to generate
    snapshot of themselves.

    Decorates the class by allowing it to have:
      * A custom class to serve each snapshot. Such class
        will have a subset of attributes to serve from the object,
        and a special designed attribute ('source', by default) to
        serve the originating object. Such class will be stored
        under custom name under the generating (decorated) class.
      * An instance method (actually: property) which will yield
        the snapshot for the instance.
    """

    def wrapper(klass):
        Snapshot = namedtuple(inner_class_name, tuple(attrs_to_freeze) + (source_attr,))

        doc = """
            From the current instance collects the following attributes:
                %s
            Additionally, using the attribute '%s', collects a reference
                to the current instance.
        """ % (', '.join(attrs_to_freeze), source_attr)

        def instance_method(self):
            return Snapshot(**dict({
                k: (getattr(self, k, defaults(k)) if callable(defaults) else getattr(self, k)) for k in attrs_to_freeze
            }, **{source_attr: self}))

        instance_method.__doc__ = doc
        setattr(klass, instance_property_name, property(instance_method))
        setattr(klass, inner_class_name, Snapshot)
        return klass

    return wrapper
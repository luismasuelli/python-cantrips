from cantrips.iteration import items


class IProtocolProvider(object):
    """
    Must implement a method returning the chunk of protocol
      operations to implement. It is intended that broadcast
      traits implement this interface as well, so they can
      build the protocol automatically.
    """

    @classmethod
    def specification(cls):
        """
        Should return dict {ns => {code: direction}}
        """

        raise NotImplementedError

    @staticmethod
    def specifications(*args):
        """
        Should return a specification iterating many given providers. Note:
          If one spec declares a namespace, and another spec declares the same
          namespace, the content of the namespace will be updated with such new
          content.

        e.g. assume provider A has {'a': {'a1': 1, 'a3': 3}, 'c': {'c1': 1}} and
          B has {'a': {'a1': 1.5, 'a2': 2}, 'b': {'b1': 1}}. The resulting spec
          would be:

          {'a': {'a1': 1.5, 'a2': 2, 'a3': 3}, 'b': {'b1': 1}, 'c': {'c1': 1}}
        """

        total_specs = {}
        for provider in args:
            for key, value in items(provider.specification()):
                total_specs.setdefault(key, {}).update(value)
        return total_specs
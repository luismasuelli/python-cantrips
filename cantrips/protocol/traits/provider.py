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

    @classmethod
    def specification_handlers(cls):
        """
        Should return dict {ns => {code: handler}}. Only has sense for (server|both)-direction
          codes.
        """

        raise NotImplemented

    @staticmethod
    def specifications(*args):
        """
        Should return a specification iterating many given providers. Note:
          If one spec declares a namespace, and another spec declares the same
          namespace, the content of the namespace will be updated with such new
          content.
        """

        total_specs = {}
        for provider in args:
            for key, value in items(provider.specification()):
                total_specs.setdefault(key, {}).update(value)
        return total_specs

    @staticmethod
    def specifications_handlers(*args):
        """
        Should return a specification handlers iterating many given providers.
        """

        total_specs = {}
        for provider in args:
            for key, value in items(provider.specification_handlers()):
                total_specs.setdefault(key, {}).update(value)
        return total_specs
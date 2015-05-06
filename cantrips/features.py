from cantrips.types.exception import factory


class Feature(object):
    """
    Tries to import a specific feature.
    """
    Error = factory(['UNSATISFIED_IMPORT_REQ'])
    _FEATURES = {}

    @classmethod
    def import_it(cls):
        """
        Performs the import only once.
        """
        if not cls in cls._FEATURES:
            try:
                cls._FEATURES[cls] = cls._import_it()
            except ImportError:
                raise cls.Error(cls._import_error_message(), cls.Error.UNSATISFIED_IMPORT_REQ)
        return cls._FEATURES[cls]

    @classmethod
    def _import_it(cls):
        """
        Internal method - performs the import and returns the imported object.
        """
        return None

    @classmethod
    def _import_error_message(cls):
        """
        Internal method - displays the exception message
        """
        return None
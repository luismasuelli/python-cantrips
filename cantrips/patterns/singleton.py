class Singleton(type):
    """
    Meta-class. Implements the Singleton pattern. This pattern is, actually, borrowed.
    """
    def __init__(cls, name, bases, dict_):
        super(Singleton, cls).__init__(name, bases, dict_)
        cls._instance = None

    def __call__(cls, *args, **kw):
        """
        Each singleton class has a wrapper of __call__ which will return the
          already-created instance (without further calls to __new__ or __init__).
        """
        if cls._instance is None:
            cls._instance = super(Singleton, cls).__call__(*args, **kw)
        return cls._instance

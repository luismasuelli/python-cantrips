from functools import wraps


def customizable(subdecorator, **defaults):
    """
    Allows to create customizable decorators. Such decorators (like Django's django.contrib.auth.login_required)
      can be used in two different ways:

      # positionally

      @decorator
      def myfunc(...):
          ...

    and

      # namely

      @decorator(**opts)
      def myfunc(...):
          ...

    Being both of them a different type of call (first-order call, and higher-order call). For this to work, it
      needs (as first/subdecorator= argument) a function to be passed which takes (function, option1=v1, option2=v2,
      ...) arguments. Such function is the actual implementation of the decorator (being the first argument as
      positional - the wrapped function - and the remaining arguments just parameters for the implementation). It
      also can have many by-name arguments which will act as default arguments for the decorator implementation
      (and so, the specified by-name arguments must be expected/well-received by the implementation).

    The returned value is a function which can be invoked either positionally (only one argument: the function to wrap)
      or by-name (arguments as needed, but expected in the decorator's implementation).

    If called positionally, it is a decorator that wraps a function by calling the implementation passing the to-wrap
      function AND the default parameters as specified.

    If called by-name, its return value is a decorator that wraps a function by calling the implementation passing
      the to-wrap function AND the default parameters updated by the by-name parameters.

    :param subdecorator: Decorator implementation. Must take a function as positional argument, and many arguments (as
      desired) which will be passed by-name and will customize the implementation's behavior.
    :param defaults: Default by-name arguments for the implementation (additional reason to have them separate is that
      perhaps the user has no control over the function which will be the decorator's implementation).
    :return: a function which will act as decorator (if called positionally) or as a function returning a decorator
      (if called by-name).
    """

    @wraps(subdecorator, assigned=('__name__', '__module__'))
    def _decorator(*func, **options):
        lfunc = len(func)
        lopts = len(options)

        if lfunc and lopts:
            raise TypeError("Cannot specify both positional arguments and options")
        if not lfunc and not lopts:
            raise TypeError("Either positional arguments or options must be specified")

        if lfunc > 1:
            raise TypeError("Cannot specify more than one positional argument")
        elif lfunc == 1:
            # case 1 - the returned function is being used as the direct
            # decorator. It must call the subdecorator using the values by
            # default AND the wrapped function.
            return subdecorator(func[0], **defaults)
        else:
            # case 2 - the returned function is passed more options and so
            # will return the decorator.
            return lambda f: subdecorator(f, **dict(defaults, **options))
    return _decorator
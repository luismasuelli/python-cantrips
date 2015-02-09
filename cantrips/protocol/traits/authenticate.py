from functools import wraps


class IAuthCheck(object):

    def auth_check(self, socket, state=True):
        """
        Checks whether the user is in the specified log state.
        This means:
          It must check whether the user is logged in (if state=True)
          or not (if state=False).
        The implementation should return True if the user matches the
          specified logged state.
        """
        raise NotImplementedError

    @staticmethod
    def login_required(f):
        """
        Wraps a method by ensuring that sockets (first argument)
          are logged in.
        """
        @wraps(f)
        def wrapped(self, socket, *args, **kwargs):
            if self.auth_check(socket, True):
                f(self, socket, *args, **kwargs)
        return wrapped

    @staticmethod
    def logout_required(f):
        """
        Wraps a method by ensuring that sockets (first argument)
          are not logged in.
        """
        @wraps(f)
        def wrapped(self, socket, *args, **kwargs):
            if self.auth_check(socket, False):
                f(self, socket, *args, **kwargs)
            return wrapped
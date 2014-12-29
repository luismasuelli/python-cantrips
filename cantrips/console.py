from future.builtins.misc import input as line_input


class _Getch:
    """
    Gets a single character from standard input. Does not echo to the screen.
    """
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()

    def __call__(self): return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys

    def __call__(self):
        import sys, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        return msvcrt.getch()


getch = _Getch()
igetch = lambda: getch().lower()
igetch.__doc__ = """
Gets a single character from standard input. Does not echo to the screen.
Converts it to lowercase, so it is not important the actual input case.
"""


def input(message, until, single_char=False, transform=lambda a: a):
    """
    Keeps asking for input (each time in a new line) until a condition
        over the input text evaluates to true. Returns the input. This
        input can be done using text input or character input.
    """
    def _getch(message):
        print message,
        return getch()

    while True:
        text = transform(line_input(message) if not single_char else _getch(message))
        if until(text):
            return text


def input_option(message, options="yn", error_message=None):
    """
    Reads an option from the screen, with a specified prompt.
        Keeps asking until a valid option is sent by the user.
    """
    def _valid(character):
        if character not in options:
            print error_message % character
    return input("%s [%s]" % (message, options), _valid, True, lambda a: a.lower())
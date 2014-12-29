import sys
from copy import deepcopy, copy

from .expression import Expression, IdentityExpression
from .undefined import Undefined
from cantrips.types.exception import factory


class Scope(object):

    Error = factory({'ALREADY_IN_PHASE': 1,
                               'MAX_DIGEST_LOOPS': 2})

    class Evaluable(object):

        def __init__(self, scope, expr, globals_, locals_):
            self.expr = expr
            self.globals = globals_
            self.locals = locals_
            self.locals.update({'self': scope})

        def do(self):
            return eval(self.expr, self.globals, self.locals)

    class Watch(object):

        def __init__(self, scope, expr, callback, deep=False):
            self.scope = scope
            self.expr = expr
            self.callback = callback
            self.copy = deepcopy if deep else copy
            self.last = UNDEFINED

        def do(self):
            value = self.copy(self.scope['$eval'](self.expr))
            if value != self.last:
                self.callback(self.scope, value, self.last)
                self.last = value
                return True
            return False

    def __init__(self, **kwargs):
        self.__watchers = {}
        self.__phases = set()
        for k, v in kwargs.iteritems():
            if not k.startswith('__'):
                setattr(self, k, v)

    def __watch(self, expression, func, deep=False):
        """
        Creates a watch for a given expression.
        """
        if isinstance(expression, (list, tuple, set, frozenset, dict, Expression)) or callable(expression):
            watcher = self.Watch(self, expression, func, deep=deep)
        else:
            frame_ = sys._getframe(1)
            watcher = self.Watch(self, self.Evaluable(self, expression, frame_.f_globals, frame_.f_locals), func, deep=deep)
        self.__watchers[id(watcher)] = watcher
        return lambda: self.__unwatch(id(watcher))

    def __unwatch(self, key):
        """
        Removes an already-created watch.
        """
        self.__watchers.pop(key, None)

    def __no_recursive_push(self, phase):
        """
        Enters an internal state, disallowing recursion and reentrancy.
        """
        if phase in self.__phases:
            raise self.Error("Cannot enter phase '%s' - already in" % phase, self.Error.ALREADY_IN_PHASE, phase=phase)
        else:
            self.__phases.add(phase)

    def __no_recursive_pop(self, phase):
        """
        Exits an internal state, so another entrance can be made.
        """
        self.__phases.discard(phase)

    def __digest(self):
        """
        Performs a digest cycle.
        """
        last_dirty_watch = None
        allowed_loops = 5
        current_loops = 0
        dirty = True

        self['$$nrpush']('digest')

        #evaluamos watches
        while dirty:
            #verificamos en que iteracion estamos
            if current_loops == allowed_loops:
                raise self.Error("Max iterations count (%d) reached" % allowed_loops, self.Error.MAX_DIGEST_LOOPS, max_loops=allowed_loops)
            current_loops += 1

            #realizamos vuelta de watchers
            for k, watch in self.__watchers.iteritems():
                #si ya dimos toda la vuelta analizando watches, cortamos
                if last_dirty_watch == watch:
                    dirty = False
                    break
                if watch.do():
                    last_dirty_watch = watch

            #si no hubo ninguno sucio a esta altura (tras evaluar todos los watch), entonces cortamos
            if last_dirty_watch is None:
                dirty = False

        self['$$nrpop']('digest')

    def __eval(self, expr):
        """
        Evaluates an expression in the current scope.

        Advantages and caveats of different expression types:
        * "_" expressions: You can detect in a fine-grained way, when an
        undefined value is produced. However you are limited in the usage
        of global values and expressions since they will directly affect
        the expression objects (e.g. [_.a] * 8 would evaluate eagerly to
        something like (actually, not identical, but it is just an example)
        [_.a, _.a, _.a, _.a, _.a, _.a, _.a, _.a] instead of lazily evaluating).
        * lambda expressions: Cannot fine-grain-detect an undefined value
        (the whole expression will return undefined if an attribute does
        not exist or an item does not exist - undefined values will be
        fine-grain-detected only if a preexistent undefined value was passed
        beforehand to such expression), however it can use global functions
        or values since a lambda expression is lazily evaluated.
        * Evaluables: You create an evaluable by passing a string with a valid
        python expression to be evaluated. The python expression considers the
        lexical scope in the caller scope. It has the same advantages and
        caveats of the lambda expressions. The 'self' name refers this scope
        object.
        """
        if isinstance(expr, (list, tuple, set, frozenset, dict, Expression)):
            return Expression.eval(expr, self)
        elif callable(expr):
            try:
                return expr(self)
            except (AttributeError, IndexError, KeyError, TypeError):
                return UNDEFINED
        elif isinstance(expr, self.Evaluable):
            try:
                return expr.do()
            except (AttributeError, IndexError, KeyError, TypeError):
                return UNDEFINED
        return UNDEFINED

    def __apply(self, expr):
        """
        Performs an evaluation of an expression, and then a digest cycle.
        """
        try:
            self['$$nrpush']('apply')
            return self['$eval'](expr)
        except Exception as e:
            raise e
        finally:
            self.__digest()
            self['$$nrpop']('apply')

    def __getitem__(self, item):
        """
        Dispatches to an internal method.
        itemgetter is not allowed for scopes other than for
            these internal methods.
        """
        if item == '$watch':
            return self.__watch
        if item == '$unwatch':
            return self.__unwatch
        if item == '$$digest':
            return self.__digest
        if item == '$eval':
            return self.__eval
        if item == '$apply':
            return self.__apply
        if item == '$$nrpush':
            return self.__no_recursive_push
        if item == '$$nrpop':
            return self.__no_recursive_pop
        raise KeyError(item)


ROOT = IdentityExpression()
UNDEFINED = Undefined()
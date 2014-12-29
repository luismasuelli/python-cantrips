import operator

from .undefined import Undefined
from cantrips.types.exception import factory


class Expression(object):

    Error = factory({'INVALID_ATTRIBUTE': 1})

    def __expr_evaluate__(self, scope):
        return None

    @classmethod
    def eval(cls, value, scope):
        if isinstance(value, Expression):
            return value.__expr_evaluate__(scope)
        for type_ in (list, tuple, set, frozenset):
            if isinstance(value, type_):
                return type(value)(cls.eval(p, scope) for p in value)
        if isinstance(value, dict):
            return type(value)((cls.eval(k, scope), cls.eval(v, scope)) for k, v in value.iteritems())
        return value

    @classmethod
    def digest(cls, value, collected=()):
        """
        Calcula recursivamente, usando todas las vias que puede, un digest
        para el objeto. En este sentido, todo se reduce al id(_) del objeto.
        """

        if value in collected:
            #objetos a los que llegamos recursivamente
            #    deben devolver su id(_)
            return id(value)
        collected += (value,)

        for type_ in (list, tuple, set, frozenset):
            #objetos secuenciales
            #    deben promediar el digest de sus elementos
            if isinstance(value, type_):
                return sum(cls.digest(p, collected) for p in value) // len(value)

        if isinstance(value, dict):
            #objetos de doble secuencia
            #    deben promediar el digest de las claves + el digest de los valores
            return sum(cls.digest(k, collected) + cls.digest(v, collected) for k, v in value.iteritems()) // (2 * len(value))

        try:
            #objetos con atributos
            #    debemos calcular el digest de un diccionario que contiene todos los atributos
            #    excepto aquellos que comienzan con __
            return cls.digest({k: v for k, v in value.iteritems() if not k.startswith('__')}, collected)
        except AttributeError:
            #el objeto no tiene __dict__
            #    es un objeto primitivo y atomico. obtenemos su id
            return id(value)

    # Visualizacion y casteo (no compatible con python 3)

    def __str__(self):
        return UnaryExpression(str, self)

    def __unicode__(self):
        return UnaryExpression(unicode, self)

    def __repr__(self):
        return UnaryExpression(repr, self)

    def __nonzero__(self):
        return UnaryExpression(bool, self)

    def __int__(self):
        return UnaryExpression(int, self)

    def __float__(self):
        return UnaryExpression(float, self)

    def __long__(self):
        return UnaryExpression(long, self)

    def __complex__(self):
        return UnaryExpression(complex, self)

    # Comparativos

    def __lt__(self, other):
        return BinaryExpression(operator.lt, self, other)

    def __gt__(self, other):
        return BinaryExpression(operator.gt, self, other)

    def __le__(self, other):
        return BinaryExpression(operator.le, self, other)

    def __ge__(self, other):
        return BinaryExpression(operator.ge, self, other)

    def __ne__(self, other):
        return BinaryExpression(operator.ne, self, other)

    def __eq__(self, other):
        return BinaryExpression(operator.eq, self, other)

    # Accesores de componentes e iteracion

    def __len__(self):
        return UnaryExpression(len, self)

    def __iter__(self):
        return UnaryExpression(iter, self)

    def __reversed__(self):
        return UnaryExpression(reversed, self)

    def __getattr__(self, item):
        return AttributeExpression(self, item)

    def __getitem__(self, item):
        def getitem(o, i):
            try:
                return o[i]
            except (IndexError, KeyError, TypeError) as e:
                return Undefined()
        return BinaryExpression(getitem, self, item)

    def __contains__(self, item):
        return BinaryExpression(operator.contains, self, item)

    # Llamadores

    def __call__(self, *args, **kwargs):
        return CallableExpression(lambda c, a, kwa: c(*a, **kwa), self, args, kwargs)

    # Aritmeticos (simples)

    def __add__(self, other):
        return BinaryExpression(operator.add, self, other)

    def __radd__(self, other):
        return BinaryExpression(operator.add, other, self)

    def __sub__(self, other):
        return BinaryExpression(operator.sub, self, other)

    def __rsub__(self, other):
        return BinaryExpression(operator.sub, other, self)

    def __mul__(self, other):
        return BinaryExpression(operator.mul, self, other)

    def __rmul__(self, other):
        return BinaryExpression(operator.mul, other, self)

    def __div__(self, other):
        return BinaryExpression(operator.div, self, other)

    def __rdiv__(self, other):
        return BinaryExpression(operator.div, other, self)

    def __truediv__(self, other):
        return BinaryExpression(operator.truediv, self, other)

    def __rtruediv__(self, other):
        return BinaryExpression(operator.truediv, other, self)

    def __floordiv__(self, other):
        return BinaryExpression(operator.floordiv, self, other)

    def __rfloordiv__(self, other):
        return BinaryExpression(operator.floordiv, other, self)

    def __mod__(self, other):
        return BinaryExpression(operator.mod, self, other)

    def __rmod__(self, other):
        return BinaryExpression(operator.mod, other, self)

    def __divmod__(self, other):
        return BinaryExpression(divmod, self, other)

    def __rdivmod__(self, other):
        return BinaryExpression(divmod, other, self)

    def __pow__(self, power, modulo=None):
        return TernaryExpression(pow, self, power, modulo)

    def __rpow__(self, power, modulo=None):
        return TernaryExpression(pow, power, self, modulo)

    def __lshift__(self, other):
        return BinaryExpression(operator.lshift, self, other)

    def __rlshift__(self, other):
        return BinaryExpression(operator.lshift, other, self)

    def __rshift__(self, other):
        return BinaryExpression(operator.rshift, self, other)

    def __rrshift__(self, other):
        return BinaryExpression(operator.rshift, other, self)

    def __neg__(self):
        return UnaryExpression(operator.neg, self)

    def __pos__(self):
        return UnaryExpression(operator.pos, self)

    def __abs__(self):
        return UnaryExpression(operator.abs, self)

    # Bitwise

    def __and__(self, other):
        return BinaryExpression(operator.and_, self, other)

    def __rand__(self, other):
        return BinaryExpression(operator.and_, other, self)

    def __or__(self, other):
        return BinaryExpression(operator.or_, self, other)

    def __ror__(self, other):
        return BinaryExpression(operator.or_, other, self)

    def __xor__(self, other):
        return BinaryExpression(operator.xor, self, other)

    def __rxor__(self, other):
        return BinaryExpression(operator.xor, other, self)

    def __invert__(self):
        return UnaryExpression(operator.invert, self)

    # Otros

    def __index__(self):
        return UnaryExpression(operator.index, self)

    def __oct__(self):
        return UnaryExpression(oct, self)

    def __hex__(self):
        return UnaryExpression(hex, self)


class IdentityExpression(Expression):

    def __init__(self):
        super(IdentityExpression, self).__init__()

    def __expr_evaluate__(self, scope):
        x = scope
        return x


class OperatorExpression(Expression):

    def __init__(self, func, args):
        super(OperatorExpression, self).__init__()
        self.__func = func
        self.__args = args

    def __expr_evaluate__(self, scope):
        x = self.__func(*self.eval(self.__args, scope))
        return x


class UnaryExpression(OperatorExpression):

    def __init__(self, func, expr):
        super(UnaryExpression, self).__init__(func, [expr])


class AttributeExpression(UnaryExpression):

    def __init__(self, expr, item):
        if item.startswith('__'):
            raise Expression.Error("Cannot reference attributes starting with double underscore", code=Expression.Error.INVALID_ATTRIBUTE)
        super(AttributeExpression, self).__init__(lambda obj: getattr(obj, item, Undefined()), expr)


class BinaryExpression(OperatorExpression):

    def __init__(self, func, expr1, expr2):
        super(BinaryExpression, self).__init__(func, [expr1, expr2])


class TernaryExpression(OperatorExpression):

    def __init__(self, func, expr1, expr2, expr3):
        super(TernaryExpression, self).__init__(func, [expr1, expr2, expr3])


class CallableExpression(Expression):

    def __init__(self, func, expr, args, kwargs):
        super(CallableExpression, self).__init__()
        self.__func = func
        self.__expr = expr
        self.__args = args
        self.__kwargs = kwargs

    def __expr_evaluate__(self, scope):
        args = self.eval(self.__args, scope)
        kwargs = self.eval(self.__kwargs, scope)
        expr = self.eval(self.__expr, scope)
        x = self.__func(expr, args, kwargs)
        return x
class Undefined(object):

    I = None

    # Identidad del objeto

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls.I, cls):
            cls.I = super(Undefined, cls).__new__(cls, *args, **kwargs)
        return cls.I

    def __hash__(self):
        return 0

    # Visualizacion y casteo (no compatible con python 3)

    def __str__(self):
        return 'undefined'

    def __unicode__(self):
        return u'undefined'

    def __repr__(self):
        return 'Undefined()'

    def __nonzero__(self):
        return False

    def __int__(self):
        return 0

    def __float__(self):
        return 0.0

    def __long__(self):
        return 0l

    def __complex__(self):
        return 0j

    # Comparativos

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return False

    def __le__(self, other):
        return False

    def __ge__(self, other):
        return False

    def __ne__(self, other):
        return True

    def __eq__(self, other):
        return False

    # Accesores de componentes e iteracion

    def __len__(self):
        return self

    def __iter__(self):
        return self

    def __reversed__(self):
        return self

    def __getattr__(self, item):
        if item.startswith('__') and item.endswith('__') and len(item) >= 4:
            super(Undefined, self).__getattr__(self, item)
        return self

    def __getitem__(self, item):
        return self

    def __contains__(self, item):
        return False

    # Llamadores

    def __call__(self, *args, **kwargs):
        return self

    # Aritmeticos (simples)

    def __add__(self, other):
        return self

    def __radd__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __rsub__(self, other):
        return self

    def __mul__(self, other):
        return self

    def __rmul__(self, other):
        return self

    def __div__(self, other):
        return self

    def __rdiv__(self, other):
        return self

    def __truediv__(self, other):
        return self

    def __rtruediv__(self, other):
        return self

    def __floordiv__(self, other):
        return self

    def __rfloordiv__(self, other):
        return self

    def __mod__(self, other):
        return self

    def __rmod__(self, other):
        return self

    def __divmod__(self, other):
        return self

    def __rdivmod__(self, other):
        return self

    def __pow__(self, power, modulo=None):
        return self

    def __rpow__(self, power, modulo=None):
        return self

    def __lshift__(self, other):
        return self

    def __rlshift__(self, other):
        return self

    def __rshift__(self, other):
        return self

    def __rrshift__(self, other):
        return self

    def __neg__(self):
        return self

    def __pos__(self):
        return self

    def __abs__(self):
        return self

    # Bitwise

    def __and__(self, other):
        return self

    def __rand__(self, other):
        return self

    def __or__(self, other):
        return self

    def __ror__(self, other):
        return self

    def __xor__(self, other):
        return self

    def __rxor__(self, other):
        return self

    def __invert__(self):
        return self

    # Otros

    def __index__(self):
        return self

    def __oct__(self):
        return '0'

    def __hex__(self):
        return '0x0'
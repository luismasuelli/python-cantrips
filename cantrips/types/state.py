from .exception import factory


class State(object):

    Error = factory(['CANNOT_BE_EMPTY', 'INVALID_DEFAULT_STATE', 'INVALID_STATE'])

    def __init__(self, master_set, default):
        if not len(master_set):
            raise self.Error("Master set can't be empty",
                             self.Error.CANNOT_BE_EMPTY)
        self.__master_set = master_set.copy()
        if default not in self.__master_set:
            raise self.Error("Default value must be a value in the master_set",
                             self.Error.INVALID_DEFAULT_STATE, default=default)
        self.__default = default
        self.__state = default

    @property
    def master_set(self):
        return self.__master_set

    @master_set.setter
    def master_set(self, value):
        if not len(value):
            raise self.Error("Master set can't be empty",
                             self.Error.CANNOT_BE_EMPTY)
        if self.__default not in value:
            self.__default = iter(value).next()
        if self.__state not in value:
            self.__state = self.__default
        self.__master_set = value.copy()

    def go(self, state):
        if state not in self.master_set:
            raise self.Error("State %s not belonging to %s" % (state, self.master_set),
                             self.Error.INVALID_STATE, state=state)
        self.__state = state

    def get(self):
        return self.__state

    def back(self):
        self.__state = self.__default

    @property
    def default(self):
        return self.__default

    @default.setter
    def default(self, value):
        if value not in self.master_set:
            raise self.Error("Default state %s not belonging to %s" % (value, self.master_set),
                             self.Error.INVALID_DEFAULT_STATE, default=value)
        self.__default = value

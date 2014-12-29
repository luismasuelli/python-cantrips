from .exception import factory


class Flags(object):
    """
    Describes a flag set guided by a master flag set.
    If the master flag set changes, then only the flags belonging to the new master flag set
      will remain, while others will be discarded.
    """

    Error = factory(['INVALID_FLAG'])

    def __init__(self, master_set):
        self.__master_set = master_set.copy()
        self.__inner_set = set()

    @property
    def master_set(self):
        return self.__master_set

    @master_set.setter
    def master_set(self, value):
        self.__master_set = value.copy()
        self.__inner_set = self.__inner_set.intersection(value)

    def on(self, flag):
        if flag not in self.master_set:
            raise self.Error("Flag value %s not belonging to set: %s" % (flag, self.master_set),
                             self.Error.INVALID_FLAG, flag=flag)
        self.__inner_set.add(flag)

    def get(self, flag):
        return flag in self.__inner_set

    def off(self, flag):
        if flag not in self.master_set:
            raise self.Error("Flag value %s not belonging to set: %s" % (flag, self.master_set),
                             self.Error.INVALID_FLAG, flag=flag)
        self.__inner_set.discard(flag)

    @property
    def all(self):
        return self.__inner_set.copy()
class Result:
    """
    Contains all match data for a given file i.e how highly it scores,
    which processors flagged it as suspicious etc.
    """
    def __init__(self):
        self.rules = []
        self.strings = []
        self.score = 0

    def __iter__(self):
        for key in self.__dict__:
            yield key

    def __getitem__(self, attr):
        return getattr(self, attr)

    def __setitem__(self, attr, value):
        return setattr(self, attr, value)

    def merge_with(self, result: dict) -> None:
        """
        Merge the values from the given Result|dict into this object
        """
        for attr in self:
            if result and attr in result:
                assert isinstance(result[attr], type(self[attr]))
                self[attr] += result[attr]

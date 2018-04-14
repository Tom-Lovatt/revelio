class Result:
    """
    Contains all match data for a given file i.e how highly it scores,
    which processors flagged it as suspicious etc.
    """
    DEFAULT_SUSPICIOUS_THRESHOLD = 5

    def __init__(self, suspicious_threshold=DEFAULT_SUSPICIOUS_THRESHOLD):
        self.rules = []
        self.strings = []
        self.score = 0
        self.suspicious_threshold = suspicious_threshold

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

    def is_suspicious(self) -> bool:
        """
        Check if the Result's score is high enough to be flagged
        as suspicious
        """
        return self.score >= self.suspicious_threshold

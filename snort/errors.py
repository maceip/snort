"""Expected request failures, distinguished from storage/runtime failures."""


class RequestError(ValueError):
    pass


class ConflictError(RequestError):
    pass


class NotFoundError(KeyError):
    pass

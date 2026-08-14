"""Shared failure type for the fixture-only platform-policy facade."""


class PolicyFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

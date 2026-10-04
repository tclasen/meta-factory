"""Shared case signals retain identity when the grader runs with python -m."""


class Inconclusive(Exception):
    """The required test precondition could not be established."""


class Untested(Exception):
    """No observation procedure was executed for this criterion."""

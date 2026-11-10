"""Shared result format for all reconnaissance modules."""


def make_result(status: str, message: str = "", data=None) -> dict:
    """
    status: 'completed' | 'warning' | 'error' | 'pending'
    Every module returns this same shape so the dashboard can treat them uniformly.
    """
    return {"status": status, "message": message, "data": data if data is not None else {}}
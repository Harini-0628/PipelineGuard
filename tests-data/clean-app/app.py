import ast
import hashlib


def calc(expr: str):
    return ast.literal_eval(expr)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

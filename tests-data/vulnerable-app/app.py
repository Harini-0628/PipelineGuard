"""Deliberately vulnerable sample used ONLY to exercise PipelineGuard scanners. Never deploy."""
import hashlib
import subprocess
import sqlite3

import yaml


def run(user_cmd):
    return subprocess.run("ls " + user_cmd, shell=True, capture_output=True)


def calc(expr):
    return eval(expr)


def load(blob):
    return yaml.load(blob)


def digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def lookup(conn: sqlite3.Connection, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()

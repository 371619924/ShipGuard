import subprocess

def process(value):
    return subprocess.run(["printf", "%s", value], shell=False, check=True)

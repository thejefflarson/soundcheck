# Test case: integrity-failures (A08:2025)
import pickle
import yaml

def load_user_session(session_data):
    # BUG: pickle.loads on user-supplied data allows arbitrary code execution
    return pickle.loads(session_data)

def load_config(config_str):
    # BUG: yaml.load without Loader can execute arbitrary Python
    return yaml.load(config_str)

def download_and_run_update(url):
    import urllib.request
    import subprocess
    # BUG: downloads and executes without signature verification
    urllib.request.urlretrieve(url, "/tmp/update.sh")
    subprocess.run(["/bin/bash", "/tmp/update.sh"])

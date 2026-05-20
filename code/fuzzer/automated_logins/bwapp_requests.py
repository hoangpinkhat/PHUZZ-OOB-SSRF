import json
import os

import requests


def main():
    s = requests.Session()

    # Install / reset the DB
    s.get("http://web/install.php?install=yes")

    # Login
    s.post("http://web/login.php",
           data={"login": "bee", "password": "bug", "security_level": "0",
                 "form": "submit"})

    cookies = s.cookies.get_dict()

    node_id = os.environ.get('FUZZER_NODE_ID', None)
    cookie_path = os.environ.get('FUZZER_COOKIE_PATH', None)

    if node_id:
        file_path = os.path.join("/shared-tmpfs", f"cookies_node{node_id}.json")
    elif cookie_path:
        file_path = os.path.join(cookie_path, "cookies.json")
    else:
        raise ValueError(
            "Either FUZZER_NODE_ID or COOKIE_PATH environment variable must be set!")

    with open(file_path, "w") as f:
        json.dump(cookies, f)


if __name__ == "__main__":
    main()

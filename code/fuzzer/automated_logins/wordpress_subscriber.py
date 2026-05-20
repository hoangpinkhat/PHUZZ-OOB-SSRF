import json
import os
import requests

def main():
    """Login as subscriber1/subscriber1 to WordPress."""
    s = requests.Session()

    # Fetch login page (sets testcookie)
    s.get("http://web/wp-login.php")

    # Submit credentials
    s.post("http://web/wp-login.php", data={
        "log":       "subscriber1",
        "pwd":       "subscriber1",
        "wp-submit": "Log In",
        "redirect_to": "/wp-admin/",
        "testcookie": "1",
    }, allow_redirects=True)

    cookies = s.cookies.get_dict()

    node_id   = os.environ.get("FUZZER_NODE_ID")
    file_path = os.path.join("/shared-tmpfs", f"cookies_node{node_id}.json")

    with open(file_path, "w") as f:
        json.dump(cookies, f)

if __name__ == "__main__":
    main()

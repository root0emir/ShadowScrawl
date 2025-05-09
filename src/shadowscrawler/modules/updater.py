import subprocess


def check_version():
    try:
        subprocess.run(["git", "branch"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        subprocess.run(["git", "init"], capture_output=True)
        subprocess.run(
            [
                "git",
                "remote",
                "add",
                "origin",
                "https://github.com/root0emir/ShadowScrawl.git",
            ],
            capture_output=True,
        )

    print("Checking for latest stable release...")
    branch_out = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True
    )
    branch = branch_out.stdout
    if branch == "master":
        update_out = subprocess.run(
            ["git", "pull", "origin", "master"], capture_output=True, text=True
        )
        if "Already up to date." in update_out.stdout:
            print("ShadowScrawl is already up-to-date.")
        else:
            print("ShadowScrawl has successfully updated to the latest stable version.")
    else:
        update_out = subprocess.run(
            ["git", "pull", "origin", "dev"], capture_output=True, text=True
        )
        if "Already up to date." in update_out.stdout:
            print("ShadowScrawl is already up-to-date.")
        else:
            print("ShadowScrawl has successfully updated to the latest stable version.")

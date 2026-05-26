import os
import re

if os.path.exists("results.txt"):
    os.remove("results.txt")

# Open the file and start parsing
with open(r"/var/log/auth.log") as logFile:  # CHANGE THIS TO YOUR LOG FILE PATH
    hostRecords = []  # An array of dictionaries which will store records multiple users
    sshRecords = []  # An array of dictionaries which will store records of multiple ssh attempts

    # This portion goes thorugh and finds failed user and ssh logins
    for line in logFile:
        # Need to find failed login attempts
        if line.find("authentication failure") != -1:
            # First extracts the user that failed
            nameLocation = re.search("\\buser=\\b", line)
            endIndex = None
            if nameLocation != None:
                endIndex = nameLocation.span()[1]

            username = line[endIndex:-1]
            exists = False
            # Figure out how many times failed
            if endIndex != None:
                for record in hostRecords:
                    if (
                        record["username"] == username
                    ):  # Checks to see if the same user failed again
                        record["failure count"] = record["failure count"] + 1
                        exists = True
                        break
                if not exists:
                    hostRecords.append({"username": username, "failure count": 1})

        # Checks for failed login attempts on ssh servers
        if re.search(r"\sFailed password\s", line) is not None:
            # First extract the user, ip address, and port from the failed ssh login
            line_components = line.split(" ")
            username = line_components[8]
            ip_addr = line_components[10]
            port = line_components[12]

            # Figure out how many times a failed attempt occuered
            exists = False
            for record in sshRecords:
                if (
                    ip_addr == record["ip_address"]
                ):  # Checks to see if the same ip address attempted logins (tends to change less)
                    record["failure count"] = record["failure count"] + 1
                    if username not in record["usernames"]:
                        record["usernames"].append(username)
                    if port not in record["port"]:
                        record["port"].append(port)
                    exists = True
                    break
            if not exists:
                sshRecords.append(
                    {
                        "ip_address": ip_addr,
                        "failure count": 1,
                        "usernames": [username],
                        "port": [port],
                    }
                )

    # This portion is for flagging host/ssh login fails and writes those flagged to a text file
    with open("results.txt", "x") as resultsFile:
        resultsFile.write("-----Suspicious host user login attempts-----\n")
        for record in hostRecords:
            if record["failure count"] >= 5:
                resultsFile.write(
                    "Username: "
                    + record["username"]
                    + ", Failed Login Attempts: "
                    + str(record["failure count"])
                    + "\n"
                )

        resultsFile.write("\n-----Suspicious ssh login attempts-----\n")
        s = ","
        for record in sshRecords:
            if record["failure count"] >= 5:
                resultsFile.write(
                    "IP Address: "
                    + record["ip_address"]
                    + ", Failed Login Attempts: "
                    + str(record["failure count"])
                    + ", Usernames: ["
                    + s.join(record["usernames"])
                    + "], Ports: "
                    + s.join(record["port"])
                    + "\n"
                )

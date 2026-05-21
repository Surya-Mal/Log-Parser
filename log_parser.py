import re

# Open the file and start parsing
with open(r"/var/log/auth.log") as logFile:  # CHANGE THIS TO YOUR LOG FILE PATH
    records = []  # An array of dictionaries which will store records multiple users

    # This portion goes thorugh and finds failed user and ssh logins
    for line in logFile:
        # Need to find failed login attempts
        if line.find("authentication failure") != -1:
            # First extracts the user that failed and figure out how many times failed
            nameLocation = re.search("\\buser=\\b", line)
            endIndex = None
            if nameLocation != None:
                endIndex = nameLocation.span()[1]

            username = line[endIndex:-1]
            exists = False
            if endIndex != None:
                for record in records:
                    if (
                        record["username"] == username
                    ):  # Checks to see if the same user failed again
                        record["failure count"] = record["failure count"] + 1
                        exists = True
                        break
                if not exists:
                    records.append({"username": username, "failure count": 1})
    print(records)

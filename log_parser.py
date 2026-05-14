# Open the file and start parsing
with open(r"/var/log/auth.log") as logFile:  # CHANGE THIS TO YOUR LOG FILE PATH
    for line in logFile:
        # Need to find failed login attempts
        if line.find("authentication failure") != -1:
            print(line)

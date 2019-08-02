#!/usr/bin/python3
""" An hourly script that checks if eth0 is ok and, if not tries to recover
"""
import time
import subprocess

output = subprocess.check_output(["ethtool", "eth0"]).decode("utf-8")


if "Speed: Unknown" in output:
    # Looks like a problem, try renegotiating and resetting interface
    output2 = subprocess.check_output(["ethtool", "-r", "eth0"]).decode("utf-8")
    #time.sleep(5)
    output3 = subprocess.check_output(["ifdown", "eth0"]).decode("utf-8")
    #time.sleep(5)
    output4 = subprocess.check_output(["ifup", "eth0"]).decode("utf-8")
    

    mailcmd = 'mail -s "XXX: Euclid eth0 down" morinpatmorin@gmail.com'.split()
    message = "\n\n".join([output, output2, output3, output4])
    message = bytes(message, "utf-8")
    p = subprocess.Popen(mailcmd, stdin=subprocess.PIPE, 
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    output, err = p.communicate(message)
    rc = p.returncode
else:
    print("Hourly check of eth0 seems ok")

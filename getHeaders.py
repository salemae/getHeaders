import click
import requests
import json
from termcolor import colored
import colorama

Alerts = []
Warnings = []
ServerList = [
    'Apache',
    'Nginx',
    'Microsoft-IIS',
    'LiteSpeed',
    'Google Servers',
    'Node.js',
    'Tomcat',
    'Apache Traffic Server',
    'IdeaWebServer',
    'Tengine',
    'Cowboy',
    'Lighttpd'
]
@click.command()
@click.argument('uri')
@click.option('--s', default="false", help='if your looking for a specific header only')
@click.option('--useragent', default="Mozilla/5.0", help='set a User-agent')
def getHeaders(uri,s,useragent):
    """
          This script helps extract all the response headers and identifies some the
          security issue if found.

          Please note that all requests to un-trusted ssl certificates will not be alerted.

          usage example 1 - in this example we are calling for all the headers.
          [getHeader.py https://www.example.com]

          useage example 2 - in this example we are setting the user-agent
          to 'Mozilla'.
          [getHeader.py https://www.example.com --useragent Mozilla]

          useage example 3 - in this example we are calling for a specific header
          [getHeader.py https://www.example.com -s x-xss-protection]
          """
    ua = {'User-agent': useragent}
    print("host: [" + colored(uri,"yellow") + "]")
    if s is not None: print("Target header: [" + colored(s,"yellow") + "]")
    if useragent is not None: print("User-agent: [" + colored(useragent,"yellow") + "]")
    print("")
    http = requests.get(uri, ua, verify=False)
    js = json.dumps(http.headers.__dict__['_store'])
    data = json.loads(js)
    if s == "false":
        print("Response Headers:")
        headParse(data)
        print()
        print("Alerts and Warnings:")
        alerts(Warnings,"warning")
        alerts(Alerts,"alert")
    else:
        spcifyheader(s,data)

    return data

def headParse(head):
    for key in head:
        value = str(head[key])
        value = value.replace("[","")
        value = value.replace("]", "")
        value = value.replace("]", "")
        value = value.replace("'", "")
        value = value.split(",")
        if value[0] == "Date":
            print(colored(value[0], 'yellow') + ": " + colored(value[1], 'red') + colored(value[2], 'red'))
        else:
            rules(value[0],value[1])


def spcifyheader(headname,data):
    value = data[headname]
    print(value)
    return value

def rules(header,value):
    if header == "X-XSS-Protection":
        #X-XSS-Protection Rule
        print(colored(header, 'yellow') + ": " + colored(value, 'red'))
        if "0" in value:
            Warnings.append(header + " is set to 0 which means its not enabled")
        elif "1" in value:
            Alerts.append(header + " is set to 1 which means its enabled")
            if "mode=block" in value:
                Alerts.append(header + " mode block is enabled")
                if "report" in value:
                    Alerts.append(header + " XSS protection reporting is enabled")
    elif header == "X-Content-Type-Options":
        #X-Content-Type Rule
        print(colored(header, 'yellow') + ": " + colored(value, 'red'))
        if "nosniff" in value:
            Alerts.append(header + " nosniff is enabled")
        else:
            Warnings.append(header + " nosniff please set nosniff")

    elif header == "X-Frame-Options":
        # X-Frame-Options
        print(colored(header, 'yellow') + ": " + colored(value, 'red'))
        if "DENY" in value:
            Alerts.append(header + " DENY is set")
        elif "SAMEORIGIN" in value:
            Alerts.append(header + " SAMEORGIN is set")
        elif "ALLOW-FROM" in value:
            Alerts.append(header + " ALLOW-FROM is set")
        else:
            Warnings.append(header + " is not set and could lead to XFS attacks")

    elif header == "Public-Key-Pins":
        #Public-Key-Pins rules
        print(colored(header, 'yellow') + ": " + colored(value, 'red'))
        if "pin-sha256" in value:
            Alerts.append(header + " Public key hash is set")
        elif "max-age" in value:
            Alerts.append(header + " max-age is set")
    elif header == "Set-Cookie":
        # Set-Cookie Rules
        print(colored(header, 'yellow') + ": " + colored(value, 'red'))
        if "HttpOnly" in value:
            Alerts.append(header + " HttpOnly is set")
        elif "Secure" in value:
            Alerts.append(header + " Secure is set")
        else:
            Warnings.append(header + " HttpOnly and Secure attributes are not set, cookie transmission might not be protected")
    elif header == "Server":
        if header in ServerList:
            Warnings.append(header + " Possible server type and version are exposed")
    elif header == "Date":
        pass
    else:
        print(colored(header, 'yellow') + ": " + colored(value, 'red'))

def alerts(message,type):
        if type == "alert":
            for i in range(len(message)):
                print(colored("[!]", "yellow") + message[i])
                i += 1
        elif type == "warning":
            for i in range(len(message)):
                print(colored("[⚠]", "red") + message[i])
                i += 1

if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    colorama.init()
    getHeaders()

# getHeaders
This script helps extract all the response headers and identifies some the security issue if found.

### Prerequisites

Below python modules are needed for the script to function correctly

```
pip install click
pip install requests
pip install termcolor
pip install colorama
```
## Usage
```
Usage: getHeaders.py [OPTIONS] URI

  This script helps extract all the response headers and identifies some the
  security issue if found.

  Please note that all requests to un-trusted ssl certificates will not be
  alerted.

  usage example 1 - in this example we are calling for all the headers.
  [getHeader.py https://www.example.com]

  useage example 2 - in this example we are setting the user-agent to
  'Mozilla'. [getHeader.py https://www.example.com --useragent Mozilla]

  useage example 3 - in this example we are calling for a specific header
  [getHeader.py https://www.example.com -s x-xss-protection]

Options:
  --s TEXT          if your looking for a specific header only
  --useragent TEXT  set a User-agent
  --help            Show this message and exit.
```

## Example
![](https://github.com/salemae/getHeaders/blob/master/screenshot.png)

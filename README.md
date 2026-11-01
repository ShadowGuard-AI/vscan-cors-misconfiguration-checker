# vscan-cors-misconfiguration-checker
A lightweight tool to detect overly permissive Cross-Origin Resource Sharing (CORS) policies by analyzing HTTP responses and identifying wildcard origins, wildcard origins combined with credentials, or a server that reflects the probe Origin back. A response with no Access-Control-Allow-Origin header is the safe, blocking state and is not a misconfiguration. Every probe sends an Origin header. If the request fails and no response is received, the tool prints a failure line and exits non-zero instead of reporting a verdict. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-cors-misconfiguration-checker`

## Usage
`./vscan-cors-misconfiguration-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-H`: No description provided
- `--method`: No description provided
- `--data`: Data to send with POST, PUT, or other request methods that support it.

## License
Copyright (c) ShadowStrikeHQ

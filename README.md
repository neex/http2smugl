# http2smugl

## What is this

This is a tool that tests and helps to exploit HTTP request smuggling, but achieved via HTTP/2 between the attacker and the frontend.

The scheme is as follows:
1. An attacker sends a crafted HTTP/2 request to the target server, which we call _frontend_.
2. The request is (presumably) converted to HTTP/1.1 and transmitted to another, _backend_ server.

Attacker wants to find such a request that it will be seen as two separate requests by the backend server.

For the information on theory and practice on the HTTP Request Smuggling, please refer to [Portswigger Web Security academy](https://portswigger.net/web-security/request-smuggling).

## Why HTTP/2?

In HTTP/2, all HTTP headers and values are binary. That means that it is possible to contain additional spaces or even newlines. It opens possibilities to perform HTTP request smuggling in more different ways.

In general, we hope that there're implementations of HTTP/2 that are not very aware of recent research on HTTP Request Smuggling in HTTP/1.1 and do not include corresponding mitigations.

## Usage

The tool contains two subcommands: `request` and `detect`. The first one is just for crafting HTTP/2 requests: most client tools does not accept invalid headers, so it's handy to have one that sends user input to the server as-is.

The other one it `detect`. It tries various techniques of request smuggling in order to detect if the target is actually vulnerable.

### `http2smugl request`

Use this subcommand to send a (probably malformed) http2 request. The first parameter is URL, and the others are just headers in `name:value` format. Backslash escaping is supported: you can use `\r`,`\n` and `\xXX` escape codes. For example, to send a header name that contains a colon, use `\x3a` (e.g. `name\x3awith\x3acolons:value`).

### `http2smugl detect`

This subcommand tries to detect the HTTP request smuggling using various techinques. There might be some false-positives.

## How detection works

TBD

### Notes on the impact

The impact of the request smuggling attack is not high most of the times. However, there might be some scenarios when it's possible to achieve quite good impact.

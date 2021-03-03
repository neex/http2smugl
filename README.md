### This document is WIP

# http2smugl

This is a tool that helps to detect and exploit HTTP request smuggling in cases it can be achieved via HTTP/2 -> HTTP/1.1 conversion by the frontend server.

The scheme is as follows:
1. An attacker sends a crafted HTTP/2 request to the target server, which we call _frontend_.
2. The request is (presumably) converted to HTTP/1.1 and transmitted to another, _backend_ server.

The attacker wants to find such a request that it will be seen as two separate requests by the backend server. We assume that the frontend<->backend HTTP/1.1 connection uses keep-alive, and the frontend will send requests from other users to the same connection.

For the information on theory and practice on the HTTP Request Smuggling, please refer to [Portswigger Web Security Academy](https://portswigger.net/web-security/request-smuggling).

## Why focus on HTTP/2?

In HTTP/2, all HTTP headers and values are binary. That means that they can contain additional spaces or even newlines. It opens possibilities to perform HTTP request smuggling in different ways.

Another point is that some recent fixes related to HTTP Request Smuggling might be implemented only for HTTP/1.1 parsers.

In general, we hope that there are implementations of HTTP/2 that are not very aware of recent research on HTTP Request Smuggling in HTTP/1.1 and do not include corresponding mitigations.

### Have you found a single vulnerability with this?

Surprisingly, yes!

I've found a possibility to send smuggle a header with a space character through Cloudflare, thus opening a door for Cloudflare<->client smuggling (in case the software of a Cloudflare client accepts & trims header names). Here's [the blogpost](https://lab.wallarm.com/cloudflare-fixed-an-http-2-smuggling-vulnerability/).

There is also another bug bounty report that is not public yet.

However, I understand that this type of vulnerabilities must be frustratingly rare: unlike HTTP/1.1, there are not so many HTTP/2 implementations, and most of them are made with security in mind, thus rejecting suspicious or invalid headers.

## Usage

To install the tool, run `go get github.com/neex/http2smugl`.

The tool contains two subcommands: `request` and `detect`. The first one is just for crafting HTTP/2 requests: most client tools do not accept invalid headers, so it's handy to have one that sends user input to the server as-is.

The other one it `detect`. It tries various techniques of HTTP request smuggling to detect if the target is vulnerable. The detection algorithm is complicated; I appreciate it if you read through it and send me your comments. It is described below in the corresponding section.

### `http2smugl request`

Use this subcommand to send a (probably a bit malformed) http2 request. The first parameter is URL, and the others are just headers in the `name:value` format (note there's no space after the colon). Backslash escaping is supported: you can use `\r`,`\n` and `\xXX` escape codes. For example, to send a header name that contains a colon, use `\x3a` (e.g. `name\x3awith\x3acolons:value`).

### `http2smugl detect`

This subcommand tries to detect the HTTP request smuggling using various techniques. To use it, just run "http2smugl detect [HTTPS URL]".

The command will report only if it could detect that the server parses a smuggled header. To understand what does it mean, please read the next section.

## How detection works

To perform an HTTP Request Smuggling attack, we actually need to "smuggle" a single header first (either `Content-Length` or `Transfer-Encoding`). It means that we need to send a header that a) controls when the request finished b) won't be processed by the frontend, but will be processed by the backend.

That is usually achieved by modifying a header in some way: adding spaces or tabs at the end, replacing the value with a semi-equivalent etc.

The basic idea of the vulnerability detection algorithm is to detect if the server actually processes a smuggled header as if it were `Content-Length` or `Transfer-Encoding`. We do this by sending multiple requests: some with valid, and others with invalid values for the header. Then try to detect if there's a way to *distinguish* the responses from these two groups.

That is why tool output does not contain the words "vulnerable/invulnerable": it just says if it can distinguish responses that came on the requests from these two groups.

For example, consider we're trying to smuggle the `transfer-encoding` header by replacing the dash with an underscore.

If it appears that the server responds with status 400 every time we send `transfer_encoding:zalupa` and hangs when it's `transfer_encoding:chunked`, we can say that the server probably does process the header as the value for transfer encoding. Theoretically, it could be either the frontend or the backend server.

The first case is not interesting as we could send the non-smuggled version of the header anyway, and the second one is what we're looking for. As everything happens over HTTP/2, the first case is avoidable most of the time: HTTP/2 server determines the end of the request body in another way that is unrelated to the request headers and never expects the body to be in the HTTP/1.1 chunked format (the one with hexadecimal chunk lengths).

The concrete detection techniques are:
1. We send a smuggled version of `Transfer-Encoding: chunked` (e.g. `transfer_encoding:chunked`) and different bodies: valid is `0\r\n\r\n` and invalid is `999\r\n`.

   In case the responses are different, we can be sure that the backend server receives and processes the smuggled header. There's no reason for the frontend to do this: HTTP/2 doesn't use the chunked format we sent, so it would be invalid.

   We expect the backend to hang (=timeout) for the invalid requests as it waits for more data to arrive.

2. We send a smuggled version of `Transfer-Encoding` and different bodies again: `0\r\n\r\n` as valid body and `X\r\n\r\n` as invalid one.

   The case is the same as above, but instead of reading the body, we expect the backend will just validate it.

3. We send a smuggled version of the `Content-Length` header with values `1` and `-1`.

   Both values are invalid from the frontend's point of view: there's another mechanism of determining the body length in HTTP/2 and no request body is actually sent in both cases. If the responses are different, we suppose that it's the backend server who parsed the headers.

   This method is the least reliable: the frontend might issue different errors for the cases when Content-Length has an invalid value and when it does not match the actual length.

By sending multiple pairs of valid/invalid requests we can reduce the chance of random false positive. On the other side, we can stop early if we see that there is no way we could separate responses on "valid" requests from the responses on "invalid" ones.

### Smuggling techniques

The tool tries to employ multiple smuggling techniques. None of them is new and not obvious at the same time.

#### Spaces

To smuggle a header, we append a space to it. It is the most common and classic method. We hope that the header is not processed by the frontend, but is sent as-is to the backend, which strips the space.

The tool tries a variety of character as spaces: it includes ` `, `\t`, `\v`, `\x00` and the Unicode ones.

#### Underscore

To smuggle a header, we replace the dash (`-`) with an underscore (`_`). If the backend is CGI-inspired in some way, it might convert headers like `Header-Name` to the `HEADER_NAME` form, thus the dash will become underscore anyway. While determining how to parse the body, such a backend supposedly requests the value of `CONTENT_LENGTH` / `TRANSFER_ENCODING` from its' headers dictionary, and it will be there.

#### Newlines

This one is HTTP/2 specific. As HTTP/2 is a binary protocol, we can try to send newlines in the header name or value. It is prohibited by the standard, but we hope to find an implementation that still accepts this.

During the HTTP/2 -> HTTP/1.1 conversion, the header splits into two different headers, thus the request will look completely different for the backend.

To smuggle a header, we prepend a fake header and a newline before it: pair of name "Transfer-Encoding" and value "chunked" becomes name "fake" and value "fake\r\ntransfer-encoding: chunked".

#### UTF characters

If the backend uses some high-level language and does not perform enough validation of headers, it might convert the names to the uppercase before doing anything else and do it using Unicode-aware functions. Luckily, `TRANSFER-ENCODING` contains the letter `S`, which equals to `ſ` (`\u017f`) uppercased.

In the same manner, we can search for a backend that will convert the value of `Transfer-Encoding` to lowercase: we send `chunKed` instead of `chunked` with `\u212a` instead of `K`.

Of course, it is required that the frontend will pass UTF-8 header names/values to the backend.

### Known false-positives

#### Apache Traffic Server

TODO

#### ELB

TODO

#### Other WAFs

TODO

## Contacts

If you have any ideas on this topic, contact me via [@emil_lerner](https://twitter.com/emil_lerner) on Twitter or [@neexemil](https://t.me/neexemil) on Telegram - or just post an issue here on GitHub.

# http2smugl

This tool helps to detect and exploit HTTP request smuggling in cases it can be achieved via HTTP/2 -> HTTP/1.1 conversion by the frontend server.

The scheme is as follows:
1. An attacker sends a crafted HTTP/2 request to the target server, which we call _frontend_.
2. The request is (presumably) converted to HTTP/1.1 and transmitted to another, _backend_ server.

The attacker wants to find such a request that it will be seen as two separate requests by the backend server.

If the frontend<->backend HTTP/1.1 connection uses keep-alive, the frontend might send requests from other users to the same connection. If we're able to "poison" the connection by a partial request that comes after a legit one, we can retrieve the request from another user.

Other possible scenarios include bypassing frontend server protection and rewrites, cache poisoning or cache deception.

For more information on the HTTP Request Smuggling, please refer to [Portswigger Web Security Academy](https://portswigger.net/web-security/request-smuggling).

## Why focus on HTTP/2?

In HTTP/2, all HTTP headers' names and values are binary. That means that technically they can contain additional spaces or even newlines.

[RFC7540#10.3](https://tools.ietf.org/html/rfc7540#section-10.3) states that implementations that translate HTTP/2 requests to HTTP/1 must take care of the limitations on the character set that arise from such a conversion; most implementations indeed reject them. Despite this, we hope to find ones that allow such headers. They will corrupt the converted HTTP/1.1 request to the backend.

Another point is that some recent fixes related to HTTP Request Smuggling might be implemented only for HTTP/1.1 parsers.

In general, we hope that there are implementations of HTTP/2 that are not very aware of recent research on HTTP Request Smuggling in HTTP/1.1 and do not include corresponding mitigations.

### Have you found a single vulnerability with this?

Surprisingly, yes!

I've found a possibility to smuggle a header with a space character through Cloudflare, thus opening a door for Cloudflare<->client smuggling (in case the software of a Cloudflare client accepts & trims header names). Here's [the blog post](https://lab.wallarm.com/cloudflare-fixed-an-http-2-smuggling-vulnerability/).

There is also another bug bounty report that is not public yet. It makes use of the fact that custom software doesn't filter out newlines in HTTP2 headers, and the smuggling 100% happens (I can see other users' requests).

However, I understand that this type of vulnerabilities must be frustratingly rare: unlike HTTP/1.1, there are not so many HTTP/2 implementations, and most of them are made with security in mind, thus rejecting suspicious or invalid headers.

## Detection algorithm

The tool has a subcommand that tries to detect if a target vulnerable to the HTTP Request Smuggling attack automatically. The algorithm behind this feature is described in this section.

To perform an HTTP Request Smuggling attack, we actually need to "smuggle" a single header first (either `Content-Length` or `Transfer-Encoding`). It means that we need to send a header that a) controls where the request body finishes and b) is not processed by the frontend but is processed by the backend.

That is usually achieved by modifying a header in some way: adding spaces or tabs at the end of its name, replacing the value with a semi-equivalent etc.

The vulnerability detection algorithm's basic idea is to detect if the server actually processes a smuggled header as if it were `Content-Length` or `Transfer-Encoding`. We do this by sending multiple requests: some with valid and others with invalid values for the header. Then try to detect if there's a way to *distinguish* the responses from these two groups.

That is why tool output does not contain the words "vulnerable/invulnerable": it just says if it can distinguish responses that came on the requests from these two groups.

The tool considers two sets of HTTP responses to be distinguishable if at least one of the following two conditions is met:
1. The sets of their response codes do not intersect
2. The sets of lengths of the replies are separable from each other (e.g. all "valid" responses are longer than 1000 bytes and all "invalid" ones are shorter).

The timeouts are treated as a unique status code value not equal to any other; thus, the tool supersedes the classical "detect by timing" scheme.

Let us consider an example. Suppose we're trying to smuggle the `transfer-encoding` header by replacing the dash with an underscore.

If it appears that the server responds with status 400 every time we send `transfer_encoding:zalupa` and hangs when it's `transfer_encoding:chunked`, we can say that the server probably does process the header as the value for transfer encoding. Theoretically, it could be either the frontend or the backend server.

The first case is not interesting as we could send the non-smuggled version of the header anyway, and the second one is what we're looking for. As everything happens over HTTP/2, the first case is avoidable most of the time: HTTP/2 server determines the end of the request body in another way that is unrelated to the request headers and never expects the body to be in the HTTP/1.1 chunked format (the one with hexadecimal chunk lengths).

The concrete variations of detection techniques are:
1. We send a smuggled version of `Transfer-Encoding: chunked` (e.g. `transfer_encoding:chunked`) and different bodies: valid is `0\r\n\r\n` and invalid is `999\r\n`.

   In case the responses are different, we can be sure that the backend server receives and processes the smuggled header. There's no reason for the frontend to do this: HTTP/2 doesn't use the chunked format we sent, so that it would be invalid.

   We expect the backend to hang (that is, request to timeout) for the invalid requests as it waits for more data to arrive.

   This is the most reliable detection variant: if the server hangs when reading the body, something is probably gone wrong since there's no usage for HTTP/1.1 transfer encoding in HTTP/2 request.

2. We send a smuggled version of `Transfer-Encoding` and different bodies again: `0\r\n\r\n` as valid body and `X\r\n\r\n` as invalid one.

   The case is the same as above, but instead of reading the body, we expect the backend will at least validate it.

3. We send a smuggled version of the `Content-Length` header with values `1` and `-1`.

   Both values are invalid from the frontend's point of view: there's another mechanism of determining the body length in HTTP/2, and no request body is actually sent in both cases. If the responses are different, we suppose that it's the backend server who parsed the headers.

   This method is the least reliable: the frontend might issue different errors when Content-Length has an invalid value, and when it does not match the actual length.

By sending multiple pairs of valid/invalid requests, we can reduce the chance of random false positive. On the other side, we can stop early if we see that there is no way we could separate responses on "valid" requests from the responses on "invalid" ones.

### Smuggling techniques

The tool tries to employ multiple smuggling techniques by modifying a header in various ways. None of them is new and not obvious at the same time.

#### Spaces

To smuggle a header, we append a space to it. It is the most common and classic method. We hope that the header is not processed by the frontend but is sent as-is to the backend, which strips the space.

The tool tries a variety of character as spaces: it includes ` `, `\t`, `\v`, `\x00` and the Unicode ones.

#### Underscore

To smuggle a header, we replace the dash (`-`) with an underscore (`_`). If the backend is CGI-inspired in some way, it might convert headers like `Header-Name` to the `HEADER_NAME` form; thus, the dash will become underscore anyway. While determining how to parse the body, such a backend supposedly requests the value of `CONTENT_LENGTH` / `TRANSFER_ENCODING` from its headers dictionary, and it will be there.

#### Newlines

This one is HTTP/2 specific. As HTTP/2 is a binary protocol, we can try to send newlines in the header name or value. The standard prohibits it, but we hope to find an implementation that still accepts this.

During the HTTP/2 -> HTTP/1.1 conversion, the header splits into two different headers, meaning the request will look different for the backend.

To smuggle a header, we put its name and value after a newline: a header with the name "Transfer-Encoding" and the value of "chunked" becomes one with the name "fake" with the value of "fake\r\ntransfer-encoding: chunked".

#### UTF characters

Suppose the backend uses some high-level language and does not perform enough headers' validation. In that case, it might convert the names to the uppercase before doing anything else and do it using Unicode-aware functions. Luckily, `TRANSFER-ENCODING` contains the letter `S`, which is `ſ` (`\u017f`) uppercased.

Similarly, we can search for a backend that will convert the value of `Transfer-Encoding` to lowercase: we send `chunKed` instead of `chunked` with `\u212a` instead of `K`.

Of course, it is required that the frontend will pass UTF-8 header names/values to the backend.

## Usage

To install the tool, run `go get github.com/neex/http2smugl`.

The tool contains two subcommands: `request` and `detect`. The first one is just for crafting HTTP/2 requests: most client tools do not accept invalid headers, so it's handy to have one that sends user input to the server as-is.

The other one it `detect`. It tries various techniques of HTTP request smuggling to detect if the target is vulnerable. The detection algorithm is complicated; I appreciate it if you read through it and send me your comments. It is described below in the corresponding section.

### `http2smugl request`

Use this subcommand to send a (probably a bit malformed) http2 request. The first parameter is URL, and the others are just headers in the `name:value` format (note there's no space after the colon). Backslash escaping is supported: you can use `\r`,`\n` and `\xXX` escape codes. For example, to send a header name that contains a colon, use `\x3a` (e.g. `name\x3awith\x3acolons:value`).

### `http2smugl detect`

This subcommand tries to detect the HTTP request smuggling using various techniques. To use it, just run `http2smugl detect [HTTPS URL]`.

The command will output something only if it could detect that the server parses a smuggled header. To understand what does it mean, please read the corresponding section.

### HTTP/3 support

An experimental support for HTTP/3 (quic) has been implemented. However, I do not suggest using it as I did not find a single bug related to HTTP/3.

To use HTTP/3 with `request` subcommand, provide `https+h3://` proto in the URL instead of just `https`. The same is supported in the `detect` command.

There is also a `--try-http3` flag for the `request` subcommand, which changes the behaviour in case the protocol is not specified in the URL (just hostname). If the flag is present, the command will try `https+h3` proto for such entries on the command line or the targets file (as well as HTTP/2). E.g. `http2smugl detect --try-http3 www.example.com` will try  both HTTP/3 and HTTP/2, but  `http2smugl detect --try-http3 https://www.example.com/` will still try only HTTP/2.

### Known false-positives

In this section, I describe some cases when the tool says the responses are "distinguishable", but no vulnerability could exist.

#### ELB

Amazon's Elastic Load Balancer implements multiple mitigations from HTTP Request Smuggling. While not all of them reject the request by default, ELB won't reuse a connection after sending a request with "suspicious" headers. Thus an actual attack is not possible.

To detect you're dealing with ELB, you can use the `Server` response header. If it's filtered out, you can send a request with `content__length` header (note two underscores) and value -1: if it's 400, it's probably ELB or other WAF (see below).

#### Apache Traffic Server

Apache Traffic Server is mainly used at Yahoo. It processes HTTP/2 in an unusual way: it converts it to HTTP/1.1 in memory and then re-parses the resulting request. Thus, while a header technically could be "smuggled", there's no way it will result in a vulnerability: you could send the same bytes to an HTTP/1.1 connection.

The easiest way to detect you're dealing with ATS (besides the `Server` header) is by sending a `TRACE` request. If a `Max-Forwards: 0` header present in the request, ATS will return an answer to `TRACE` requests by default without forwarding it to the backend.

#### Microsoft IIS

It seems like Microsoft IIS supports decoding chunked encoding inside HTTP/2 bodies. That is strange behaviour; however, it is innocent from the security point of view.

To detect you're dealing with IIS, you can send a request with a "transfer-encoding:chunked" header and an incorrect chunked body. If you see `Microsoft-HTTPAPI` or something like this in the `Server` header, that is it.

#### Other WAFs

WAFs try to detect suspicious headers - it's their job. Sometimes it results in the tools saying "distinguishable": WAF could block something like `content_length:-1` and allow `content_length:1` just because its filters happen to come out with these decisions.

If you see a WAF in the `Server` header, it's probably a false positive.

## Contacts

If you have any ideas on this topic, contact me via [@emil_lerner](https://twitter.com/emil_lerner) on Twitter or [@neexemil](https://t.me/neexemil) on Telegram - or post an issue here on GitHub.

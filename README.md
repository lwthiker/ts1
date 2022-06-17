# TS1 - A TLS and HTTP signature and fingerprint library

TS1 is a Python library for building fingerprints of web clients.
A fingerprint in this context is a string that identifies a web client.
Unlike a cookie, it does not distinguish between web users, but rather between different client software, e.g. different browsers, command line utilities and web libraries.

TS1 can currently calculate two kinds of signatures:
* TLS signature, based on the TLS parameters in the client's TLS client hello message. Read more about TLS fingerprinting here.
* HTTP/2 signature, based on the HTTP/2 parameters in use by the client. Read more about HTTP/2 fingerprinting here.

TS1 was created as part of the work on [curl-impersonate](https://github.com/lwthiker/curl-impersonate), a [curl](https://github.com/curl/curl) fork that fakes its own TLS and HTTP/2 fingerprint to look like a browser.

**Important note**: TS1 is currently in an alpha stage. The signatures are likely to change slightly in the coming future before it stabilizies.

## TLS fingerprint

Each web client has a unique TLS fingerprint due to the multitude of ways of configuring the TLS protocol.
Specifically, TS1 relies on the TLS client hello message which is the first message sent by the client in a TLS handshake.

In TS1, the parameters of the TLS client hello are encoded into a json (truncated here for clearness):
```json
{
    "client_hello": {
        "record_version": "TLS_VERSION_1_0",
        "handshake_version": "TLS_VERSION_1_2",
        "session_id_length": 32,
        "ciphersuites": [
            "GREASE",
            4865,
            4866,
            52392,
            49171,
            49172,
            156,
            157,
            47,
            53
        ],
        "comp_methods": [
            0
        ],
        "extensions": [
            {
                "type": "server_name"
            },
            {
                "type": "extended_master_secret",
                "length": 0
            },
            {
                "type": "renegotiation_info",
                "length": 1
            },
            {
                "type": "supported_groups",
                "length": 10,
                "supported_groups": [
                    "GREASE",
                    29,
                    23,
                    24
                ]
            }
        ]
    }
}
```

The JSON is then converted to a *canonical form*, with one space after separators and keys sorted alphabetically:
```json
{"client_hello": {"ciphersuites": ["GREASE", 4865, 4866, 52392, 49171, 49172, 156, 157, 47, 53], "comp_methods": [0], "extensions": [{"type": "server_name"}, {"length": 0, "type": "extended_master_secret"}, {"length": 1, "type": "renegotiation_info"}, {"length": 10, "supported_groups": ["GREASE", 29, 23, 24], "type": "supported_groups"}], "handshake_version": "TLS_VERSION_1_2", "record_version": "TLS_VERSION_1_0", "session_id_length": 32}}
```
which is then hashed with SHA1 to produce the TS1 signature hash:
```
cfee1dd35c55244cba1a7dba771d9df61d0dca47
```

### Compared to JA3

[JA3](https://github.com/salesforce/ja3) is a library for creating TLS fingerprints which is already widely adopted. TS1 is similar to JA3 (and was inspired by it) but has the following advantages:
* TS1 signatures encode more parameters than JA3. While it is possible for two different TLS client hello messages to have the same JA3 signature, it is far less likely with TS1.
* TS1 signatures are JSON documents which are easier to read and understand by humans, and are forward-compatible with future extensions to the TLS protocol.

The disadvantage of TS1 is that its signatures, in their raw form, are much more verbose and not as succinct as JA3.

### Usage
`ts1.tls.TLSSignature` is a class that encodes a TLS client's signature. It has two important functions:
* `TLSSignature.canonicalize()` will produce the canonical JSON form.
* `TLSSignature.hash()` will return the SHA1 hash as returned by `hashlib.sha1`

TS1 comes with a utility `process_pcap()` function to extract signatures from PCAP files:
```python
import ts1

with open("/path/to/pcap", "rb") as pcap:
    for tls_client in ts1.tls.process_pcap(pcap):
        print("Client IP: {}".format(tls_client["src_ip"]))
        # TLSSignature object
        signature = tls_client["signature"]
        print("Client' TLS signature SHA1: {}".format(
            signature.hash().hexdigest()
        ))
```

## HTTP/2 fingerprint
Each web client that supports HTTP/2 sends multiple HTTP/2 frames upon initiating a connection to a server.
These frames contain various settings configured by the client.
Each web client configures these settings differently, which makes it possible to build an HTTP/2 signature to identify the client.

The HTTP/2 frames are encoded into a JSON format (truncated here for clearness):
```json
{
    "frames": [
        {
            "frame_type": "SETTINGS",
            "stream_id": 0,
            "settings": [
                {
                    "id": 1,
                    "value": 65536
                },
                {
                    "id": 4,
                    "value": 131072
                },
                {
                    "id": 5,
                    "value": 16384
                }
            ]
        },
        {
            "frame_type": "WINDOW_UPDATE",
            "stream_id": 0,
            "window_size_increment": 12517377
        },
        {
            "frame_type": "PRIORITY",
            "stream_id": 3,
            "priority": {
                "dep_stream_id": 0,
                "weight": 201,
                "exclusive": false
            }
        },
        {
            "frame_type": "HEADERS",
            "stream_id": 15,
            "pseudo_headers": [
                ":method",
                ":path",
                ":authority",
                ":scheme"
            ]
        }
    ]
}
```

which, as in the TLS case, is converted to a canonical form and hashed to produce a SHA1 hash:
```
c9bb208868a10863867841a2e5bcb3b903719784
```

### Usage
`ts1.http2.HTTP2Signature` is a class that encodes an HTTP/2 signature. It has two important functions:
* `HTTP2Signature.canonicalize()` will produce the canonical JSON form.
* `HTTP2Signature.hash()` will return the SHA1 hash as returned by `hashlib.sha1`

TS1 comes with a utility `process_nghttpd_log()` function to extract signatures from nghttpd log (nghttpd is a small HTTP/2 server):
```python
import ts1

with open("/path/to/log", "r") as logfile:
    for http2_client in ts1.http2.process_nghttpd_log(logfile.read()):
        print("Client ID: {}".format(http2_client["client_id"]))
        # HTTP2Signature object
        signature = http2_client["signature"]
        print("Client's HTTP/2 signature SHA1: {}".format(
            signature.hash().hexdigest()
        ))
```

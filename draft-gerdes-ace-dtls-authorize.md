---
coding: utf-8

title: Datagram Transport Layer Security (DTLS) Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: CoAP-DTLS
docname: draft-gerdes-ace-dtls-authorize-latest
date: 2016-10-31
category: std

ipr: trust200902
area: Security
workgroup: ACE Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Gerdes
    name: Stefanie Gerdes
    org: Universität Bremen TZI
    street: Postfach 330440
    city: Bremen
    code: D-28359
    country: Germany
    phone: +49-421-218-63906
    email: gerdes@tzi.org
 -
    ins: O. Bergmann
    name: Olaf Bergmann
    organization: Universität Bremen TZI
    street: Postfach 330440
    city: Bremen
    code: D-28359
    country: Germany
    phone: +49-421-218-63904
    email: bergmann@tzi.org
 -
    ins: C. Bormann
    name: Carsten Bormann
    org: Universität Bremen TZI
    street: Postfach 330440
    city: Bremen
    code: D-28359
    country: Germany
    phone: +49-421-218-63921
    email: cabo@tzi.org
 -
    ins: G. Selander
    name: Göran Selander
    org: Ericsson
    street: Farögatan 6
    city: Kista
    code: 164 80
    country: Sweden
    email: goran.selander@ericsson.com
 -
    ins: L. Seitz
    name: Ludwig Seitz
    org: SICS Swedish ICT AB
    street: Scheelevägen 17
    city: Lund
    code: 223 70
    country: Sweden
    email: ludwig@sics.se

normative:
  RFC2119:
  RFC3986:
  RFC4279:
  RFC6838:
  RFC5746:
  RFC6347:
  RFC7049:
  RFC7252:
  RFC5226:
  I-D.ietf-oauth-pop-architecture:
  I-D.ietf-ace-oauth-authz:

informative:
  RFC5988:
  RFC6655:
  RFC6690:
  RFC7250:
  RFC7251:
  RFC7641:
  RFC7959:
  I-D.ietf-core-object-security:
  I-D.ietf-core-resource-directory:
  I-D.ietf-ace-cbor-web-token:
  I-D.ietf-cose-msg:

entity:
        SELF: "[RFC-XXXX]"

--- abstract

This specification defines a profile for delegating client
authentication and authorization in a constrained environment by
establishing a Datagram Transport Layer Security (DTLS) channel between resource-constrained nodes.
The protocol relies on DTLS for communication security
between entities in a constrained network. A
resource-constrained node can use this protocol to delegate
management of authorization
information to a trusted host with less severe limitations regarding
processing power and memory.

--- middle


# Introduction

This specification defines a profile of the ACE framework
{{I-D.ietf-ace-oauth-authz}}.  In this profile, a client and a resource server
use CoAP {{RFC7252}} over DTLS {{RFC6347}} to communicate.  The client uses an
access token, bound to a key (the proof-of-possession key) to authorize its
access to the resource server.  DTLS provides communication security,
proof of possession, and server authentication.  Optionally the client and the
resource server may also use CoAP over DTLS to communicate with the
authorization server.  This specification supports the DTLS PSK handshake 
{{RFC4279}} and the DTLS handshake with Raw Public Keys (RPK) {{RFC7250}}. 

The DTLS PSK handshake {{RFC4279}} provides the proof-of-possession for the key
tied to the access token.  Furthermore the psk_identity parameter in the DTLS 
PSK handshake is used to transfer the access token from the client to the
resource server.

The DTLS RPK handshake {{RFC7250}} requires client authentication to provide
proof-of-possession for the key tied to the access token.  Here the access token
needs to be transferred to the resource server before the handshake is initiated,
as described in [section 8.1 of draft-ietf-ace-oauth-authz.](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-03#section-8.1)

Note: While the scope of this draft is on client and resource server
: communicating using CoAP over DTLS, it is expected that it applies
  also to CoAP over TLS, possibly with minor modifications. However,
  that is out of scope for this version of the draft.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

Readers are expected to be familiar with the terms and concepts
described in {{I-D.ietf-ace-oauth-authz}}.

# Protocol Overview {#overview}

The CoAP-DTLS profile for ACE specifies the transfer of authentication
and, if necessary, authorization information between C and RS during
setup of a DTLS session for CoAP messaging. It also specifies how a
Client can use CoAP over DTLS to retrieve an Access Token from AS for
a protected resource hosted on RS.

This profile requires a Client (C) to retrieve an Access Token for the
resource(s) it wants to access on a Resource Server (RS) as specified
in {{I-D.ietf-ace-oauth-authz}}. {{at-retrieval}} shows the
typical message flow in this scenario (messages
in square brackets are optional):

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                   AS
   | [-- Resource Request --->] |                     |
   |                            |                     |
   | [<----- AS Information --] |                     |
   |                            |                     |
   | --- Token Request  ----------------------------> |
   |                            |                     |
   | <---------------------------- Access Token ----- |
   |                               + RS Information   |

~~~~~~~~~~~~~~~~~~~~~~~
{: #at-retrieval title="Retrieving an Access Token"}

To determine the AS in charge of a resource hosted at the RS, C MAY
send an initial Unauthorized Resource Request message to RS.  RS then
denies the request and sends the address of its AS back to C.

Instead of the initial Unauthorized Resource Request message, C MAY
look up the desired resource in a
resource directory (cf. {{I-D.ietf-core-resource-directory}}).

Once C knows AS's address, it can send an Access Token request to
the /token endpoint at the AS as specified in {{I-D.ietf-ace-oauth-authz}}.
If C wants to use the CoAP RawPublicKey mode as
described in [Section 9 of RFC 7252](https://tools.ietf.org/html/rfc7252#section-9)
it MUST provide a key or key identifier within a `cnf` object in the
token request.
If AS decides that the request is to be authorized it
generates an access token response for C containing a `profile` parameter
with the value `coap_dtls` to indicate that this profile MUST be used for communication between C and RS.
Is also adds a `cnf` parameter with additional data for the establishment of a
secure DTLS channel between C and RS.  The semantics of the 'cnf' parameter depend on the type of key used between C and RS, see {{rpk-mode}} and {{psk-mode}}.

The Access Token returned by AS then can be used by C to establish a
new DTLS session with RS. When C intends to use asymmetric
cryptography in the DTLS handshake with RS, C MUST upload the Access Token to
the `/authz-info` resource on RS before starting the DTLS handshake, as
described in [section 8.1 of draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-03#section-8.1).  If only symmetric cryptography is used between C and RS, the Access Token MAY instead be transferred in the DTLS ClientKeyExchange message
(see {{psk-dtls-channel}}).

{{protocol-overview}} depicts the common protocol flow for the
DTLS profile after C has retrieved the Access Token from AS.

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                   AS
   | [--- Access Token ------>] |                     |
   |                            |                     |
   | <== DTLS channel setup ==> |                     |
   |                            |                     |
   | == Authorized Request ===> |                     |
   |                            |                     |
   | <=== Protected Resource == |                     |

~~~~~~~~~~~~~~~~~~~~~~~
{: #protocol-overview title="Protocol overview"}

The following sections specify how CoAP is used to interchange
access-related data between RS and AS so that AS can
provide C and RS with sufficient information to establish a secure
channel, and convey
authorization information specific for this communication relationship
to RS.

Depending on the desired CoAP security mode, the Client-to-AS request,
AS-to-Client response and DTLS session establishment carry slightly
different information. {{rpk-mode}} addresses the use of raw public
keys while {{psk-mode}} defines how pre-shared keys are used in this
profile.

## Unauthorized Resource Request Message {#rreq}

The optional Unauthorized Resource Request message is a request for a resource
hosted by RS for which no proper authorization is granted. RS MUST
treat any CoAP request for a resource other than `/authz-info`
as Unauthorized Resource Request message when any of the
following holds:

* The request has been received on an unprotected channel.
* RS has no valid access token for the sender of the
  request regarding the requested action on that resource.
* RS has a valid access token for the sender of the
  request, but this does not allow the requested action on the requested
  resource.

Note: These conditions ensure that RS can handle requests autonomously
once access was granted and a secure channel has been established
between C and RS. The resource `/authz-info` is publicly accessible
to be able to upload new access tokens to RS (cf. {{I-D.ietf-ace-oauth-authz}}).

Unauthorized Resource Request messages MUST be denied with a client error
response. In this response, the Resource Server SHOULD provide
proper AS Information to enable the Client to request an
access token from RS's Authorization Server as described in {{as-info}}.

The response code MUST be 4.01 (Unauthorized) in case the sender of
the Unauthorized Resource Request message is not authenticated, or if
RS has no valid access token for C. If RS has an access token for C
but not for the resource that C has requested, RS
MUST reject the request with a 4.03 (Forbidden). If RS has
an access token for C but it does not cover the action C
requested on the resource, RS MUST reject the request with a 4.05
(Method Not Allowed).

Note:
: The use of the response codes 4.03 and 4.05 is intended to prevent
  infinite loops where a dumb Client optimistically tries to access
  a requested resource with any access token received from AS.
  As malicious clients could pretend to be C to determine C's
  privileges, these detailed response codes must be used only when a
  certain level of security is already available which can be achieved
  only when the Client is authenticated.

##  AS Information {#as-info}

The AS Information is sent by RS as a response to an
Unauthorized Resource Request message (see {{rreq}}) to point the sender of the
Unauthorized Resource Request message to RS's AS. The AS
information is a set of attributes containing an absolute URI (see
Section 4.3 of {{RFC3986}}) that specifies the AS in charge of RS.

TBD: We might not want to add more parameters in the AS information because
: this would not only reveal too much information about RS's
  capabilities to unauthorized peers but also be of little value as C
  cannot really trust that information anyway.

The message MAY also contain a nonce generated by RS to ensure freshness
in case that the RS and AS do not have synchronized clocks.

{{as-info-payload}} shows an example for an AS Information message
payload using CBOR diagnostic notation.

~~~~~~~~~~
    4.01 Unauthorized
    Content-Format: application/ace+cbor
    {AS: "coaps://as.example.com/token",
     nonce: h'e0a156bb3f'}
~~~~~~~~~~
{: #as-info-payload title="AS Information payload example"}

In this example, the attribute AS points the receiver of this message
to the URI "coaps://as.example.com/token" to request access
permissions. The originator of the AS Information payload
(i.e., RS) uses a local clock that is loosely synchronized with a time
scale common between RS and AS (e.g., wall clock time). Therefore, it has included a parameter `nonce` for replay attack prevention (c.f. {{nonce}}).

Note: There is an ongoing discussion how freshness of access tokens
: can be achieved in constrained environments. This specification for
  now assumes that RS and AS do not have a common understanding of time that
  allows RS to achieve its security objectives without explicitly adding
  a nonce.

The examples in this document are written in CBOR diagnostic notation
to improve readability. {{as-info-cbor}} illustrates the binary
encoding of the message payload shown in {{as-info-payload}}.

~~~~~~~~~~
a2                                   # map(2)
    00                               # unsigned(0) (=AS)
    78 1c                            # text(28)
       636f6170733a2f2f61732e657861
       6d706c652e636f6d2f746f6b656e  # "coaps://as.example.com/token"
    05                               # unsigned(5) (=nonce)
    45                               # bytes(5)
       e0a156bb3f
~~~~~~~~~~
{: #as-info-cbor title="AS Information example encoded in CBOR"}

## Resource Access

Once a DTLS channel has been established as described in {{rpk-mode}} and {{psk-mode}}, respectively,
C is authorized to access resources covered by the Access Token it has
uploaded to the `/authz-info` resource hosted by RS.

On the server side (i.e., RS), successful establishment of the DTLS
channel binds C to the access token, functioning as a proof-of-possession associated key.  Any request that RS receives on this channel MUST be checked against these authorization rules that are associated with the identity of C.  Incoming CoAP requests that are not authorized
with respect to any Access Token that is associated with C MUST be
rejected by RS with 4.01 response as described in {{rreq}}.

Note: The identity of C is determined by the authentication process
: during the DTLS handshake. In the asymmetric case, the public key
  will define C's identity, while in the PSK case, C's identity is
  defined by the session key generated by AS for this communication.

RS SHOULD treat an incoming CoAP request as authorized
if the following holds:

1. The message was received on a secure channel that has been
   established using the procedure defined in this document.
1. The authorization information tied to the sending peer is valid.
1. The request is destined for RS.
1. The resource URI specified in the request is covered by the
   authorization information.
1. The request method is an authorized action on the resource with
   respect to the authorization information.

Incoming CoAP requests received on a secure DTLS channel
MUST be rejected

1. with response code 4.03 (Forbidden) when the resource URI specified
   in the request is not covered by the authorization information, and
1. with response code 4.05 (Method Not Allowed) when the resource URI
   specified in the request covered by the authorization information but
   not the requested action.

C cannot always know a priori if a Authorized Resource Request
will succeed. If C repeatedly gets AS Information messages (cf. {{as-info}}) as response
to its requests, it SHOULD request a new Access Token from AS in order to
continue communication with RS.

## Dynamic Update of Authorization Information {#update}

The Client can update the authorization information stored at
RS at any time. To do so, the Client requests from AS a new Access Token
for the intended action on the respective resource and uploads
this Access Token to the `/authz-info` resource on RS.

{{update-overview}} depicts the message flow where C requests a new
Access Token after a security association between C and RS has been
established using this protocol.

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                   AS
   | <===== DTLS channel =====> |                     |
   |        + Access Token      |                     |
   |                            |                     |
   | --- Token Request  ----------------------------> |
   |                            |                     |
   | <---------------------------- New Access Token - |
   |                               + RS Information   |
   |                            |                     |
   | --- Update /authz-info --> |                     |
   |     New Access Token       |                     |
   |                            |                     |
   | == Authorized Request ===> |                     |
   |                            |                     |
   | <=== Protected Resource == |                     |

~~~~~~~~~~~~~~~~~~~~~~~
{: #update-overview title="Overview of Dynamic Update Operation"}

# RawPublicKey Mode {#rpk-mode}

To retrieve an access token for the resource that C wants to access, C
requests an Access Token from AS. C MUST add a `cnf` object
carrying either its raw public key or a unique identifier for a
public key that it has previously made known to AS.

An example Access Token request from C to RS is depicted in
{{rpk-authorization-message-example}}.

~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: application/cbor
   {
     grant_type:    client_credentials,
     aud:           "tempSensor4711",
     cnf: {
       COSE_Key: {
         kty: EC2,
         crv: P-256,
         x:   h'TODOX',
         y:   h'TODOY'
       }
     }
   }
~~~~~~~~~~
{: #rpk-authorization-message-example title="Access Token Request Example for RPK Mode"}

The example shows an Access Token request for the resource identified
by the audience string "tempSensor4711" on the AS  using a raw public key.

When AS authorizes a request, it will return an Access Token and a
`cnf` object in the AS-to-Client response. Before C initiates the DTLS
handshake with RS, it MUST send a `POST` request containing the new
Access Token to the `/authz-info` resource hosted by RS. If this
operation yields a positive response, C SHOULD proceed to establish a
new DTLS channel with RS. To use raw public key mode, C MUST pass the
same public key that was used for constructing the Access Token with
the SubjectPublicKeyInfo structure in the DTLS handshake as specified
in {{RFC7250}}.

Note:
: According to {{RFC7252}}, CoAP implementations MUST support the
  ciphersuite TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_CCM\_8 {{RFC7251}}
  and the NIST P-256 curve. C is therefore expected to offer at least
  this ciphersuite to RS.

The Access Token is constructed by AS such that RS can associate the
Access Token with the Client's public key. If CBOR web tokens
{{I-D.ietf-ace-cbor-web-token}} are used as recommended in
{{I-D.ietf-ace-oauth-authz}}, the AS MUST include a `COSE_Key` object
in the `cnf` claim of the Access Token. This `COSE_Key` object MAY
contain a reference to a key for C that is already known by RS (e.g.,
from previous communication). If the AS has no certain knowledge that
the Client's key is already known to RS, the Client's public key MUST
be included in the Access Token's `cnf` parameter.

# PreSharedKey Mode {#psk-mode}

To retrieve an access token for the resource that C wants to access, C
MAY include a `cnf` object carrying an identifier for a symmetric key
in its Access Token request to AS.  This identifier can be used by AS
to determine the session key to construct the proof-of-possession
token and therefore MUST specify a symmetric key that was previously
generated by AS as a session key for the communication between C and
RS.

Depending on the requested token type and algorithm in the Access
Token request, AS adds RS Information to the response that provides C
with sufficient information to setup a DTLS channel with RS.  For
symmetric proof-of-possession keys
(c.f. {{I-D.ietf-ace-oauth-authz}}), C must ensure that the Access
Token request is sent over a secure channel that guarantees
authentication, message integrity and confidentiality. This could be,
e.g., a DTLS channel (for "coaps") or an OSCOAP
{{I-D.ietf-core-object-security}} exchange (for "coap").

When AS authorizes C it returns an AS-to-Client response with the
profile parameter set to `coap_dtls` and a `cnf` parameter carrying a
`COSE_Key` object that contains the symmetric session key to be used
between C and RS as illustrated in {{at-response}}.

<!-- msg1 -->

~~~~~~~~~~
   2.01 Created
   Content-Format: application/cbor
   Location-Path: /token/asdjbaskd
   Max-Age: 86400
   {
      access_token: b64'SlAV32hkKG ...
      (remainder of CWT omitted for brevity;
      token_type:   pop,
      alg:          HS256,
      expires_in:   86400,
      profile:      coap_dtls,
      cnf: {
        COSE_Key: {
          kty: symmetric,
          k: h'73657373696f6e6b6579'
        }
      }
   }
~~~~~~~~~~
{: #at-response title="Example Access Token response"}

In this example, AS returns a 2.01 response containing a new Access
Token.  The information is transferred as a CBOR data structure as
specified in {{I-D.ietf-ace-oauth-authz}}. The Max-Age option tells
the receiving Client how long this token will be valid.

A response that declines any operation on the requested
resource is constructed according to [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2), (cf. Section 6.3 of {{I-D.ietf-ace-oauth-authz}}).

~~~~~~~~~~
    4.00 Bad Request
    Content-Format: application/cbor
    {
      error: invalid_request
    }
~~~~~~~~~~
{: #token-reject title="Example Access Token response with reject"}

## DTLS Channel Setup Between C and RS {#psk-dtls-channel}

When C receives an Access Token from AS, it checks if the payload
contains an `access_token` parameter and a `cnf` parameter. With this
information C can initiate establishment of a new DTLS channel with
RS. To use DTLS with pre-shared keys, C follows the PSK key exchange
algorithm specified in Section 2 of {{RFC4279}} using the key conveyed
in the `cnf` parameter of the AS response as PSK when constructing the
premaster secret.

In PreSharedKey mode, the knowledge of the session key by C and RS is
used for mutual authentication between both peers. Therefore, RS must
be able to determine the session key from the Access Token. Following
the general ACE authorization framework, C can upload the Access Token
to RS's `/authz-info` resource before starting the DTLS
handshake. Alternatively, C MAY provide the most recent base64-encoded
Access Token in the `psk_identity` field of the ClientKeyExchange
message.

If RS receives a ClientKeyExchange message that contains a
`psk_identity` with a length greater zero, it MUST base64-decode its
contents and process it in the same way as an Access Token that has
been uploaded to its `/authz-info` resource. If the contents of the
`psk_identity` contained a syntactically valid Access Token, RS
continues processing the ClientKeyExchange message. Otherwise, the
DTLS session setup is terminated with an `illegal_parameter` DTLS
alert message.

Note1: As RS cannot provide C with a meaningful PSK identity hint in
: response to C's ClientHello message, RS SHOULD NOT send a
ServerKeyExchange message.

Note2:
: According to {{RFC7252}}, CoAP implementations MUST support the
  ciphersuite TLS\_PSK\_WITH\_AES\_128\_CCM\_8 {{RFC6655}}. C is
  therefore expected to offer at least this ciphersuite to RS.

This specification assumes that the Access Token is a PoP token as
described in {{I-D.ietf-ace-oauth-authz}} unless specifically stated
otherwise. Therefore, the Access Token is bound to a symmetric PoP key
that is used as session key between C and RS.

While C can retrieve the session key from the contents of the `cnf`
parameter in the AS-to-Client response, RS uses the information contained
in the `cnf` claim of the Access Token to determine the actual session
key. Usually, this is done by including a `COSE_Key` object carrying
either a key that has been encrypted with a shared secret between AS
and RS, or a key identifier that can be used by RS to lookup the
session key.

Instead of the `COSE_Key` object, AS MAY include a `COSE_KDF_Context`
object to enable RS to calculate the session key from the Access
Token. The `COSE_KDF_Context` MUST contain a `PartyUInfo` field
carrying a nonce that has been used by AS to construct the session
key. 

This specification mandates that at least the key derivation algorithm
`HKDF SHA-256` as defined in {{I-D.ietf-cose-msg}} MUST be supported.
This key derivation function is the default when no `AlgorithmID`
field is included in the `COSE_KDF_Context` object.

## Updating Authorization Information

Usually, the authorization information that RS keeps for C is updated
by uploading a new Access Token as described in {{update}}.

If the security association with RS still exists and RS has indicated
support for session renegotiation according to {{RFC5746}}, the new
Access Token MAY be used to renegotiate the existing DTLS session. In
this case, the Access Token is used as `psk_identity` as defined in
{{psk-dtls-channel}}. The Client MAY also perform a new DTLS handshake
according to {{psk-dtls-channel}} that replaces the existing DTLS session.

After successful completion of the DTLS handshake RS updates the
existing authorization information for C according to the
new Access Token.

# Security Considerations

TODO

## Unprotected AS Information

Initially, no secure channel exists to protect the communication
between C and RS. Thus, C cannot determine if the AS information
contained in an unprotected response from RS to an unauthorized
request (c.f. {#as-info}) is authentic. It is therefore advisable to
provide C with a (possibly hard-coded) list of trustworthy
authorization servers. AS information responses referring to a URI not
listed there would be ignored.

## Use of Nonces for Replay Protection {#nonce}

RS may add a nonce to the AS Information message sent as a response to
an unauthorized request to ensure freshness of an Access Token
subsequently presented to RS. While a timestamp of some granularity
would be sufficient to protect against replay attacks, using
randomized nonce is preferred to prevent disclosure of information
about RS's internal clock characteristics.

## Privacy

An unprotected response to an unauthorized request (c.f. {#as-info})
may disclose information about RS and/or its existing relationship
with C. It is advisable to include as little information as possible
in an unencrypted response. When a DTLS session between C and RS
already exists, more detailed information may be included with an
error response to provide C with sufficient information to react on
that particular error.

--- back

<!--  LocalWords:  Datagram CoAP CoRE DTLS introducer URI
 -->
<!--  LocalWords:  namespace Verifier JSON timestamp timestamps PSK
 -->
<!--  LocalWords:  decrypt UTC decrypted whitespace preshared HMAC
-->

<!-- Local Variables: -->
<!-- coding: utf-8 -->
<!-- ispell-local-dictionary: "american" -->
<!-- End: -->

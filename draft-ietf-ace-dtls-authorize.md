---
coding: utf-8

title: Datagram Transport Layer Security (DTLS) Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: CoAP-DTLS
docname: draft-ietf-ace-dtls-authorize-latest
date: 2018-03-01
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
    org: RISE SICS
    street: Scheelevägen 17
    city: Lund
    code: 223 70
    country: Sweden
    email: ludwig.seitz@ri.se

normative:
  RFC2119:
  RFC8174:
  RFC4279:
  RFC5746:
  RFC6347:
  RFC7252:
  RFC7925:
  RFC8152:
  I-D.ietf-ace-oauth-authz:
  I-D.tiloca-tls-dos-handshake:

informative:
  RFC6655:
  RFC7250:
  RFC7251:
  I-D.ietf-ace-cbor-web-token:

entity:
        SELF: "[RFC-XXXX]"

--- abstract

This specification defines a profile for delegating client
authentication and authorization in a constrained environment by
establishing a Datagram Transport Layer Security (DTLS) channel
between resource-constrained nodes.  The protocol relies on DTLS for
communication security between entities in a constrained network using
either raw public keys or pre-shared keys. A resource-constrained node
can use this protocol to delegate management of authorization
information to a trusted host with less severe limitations regarding
processing power and memory.

--- middle


# Introduction

This specification defines a profile of the ACE framework
{{I-D.ietf-ace-oauth-authz}}.  In this profile, a client and a
resource server use CoAP {{RFC7252}} over DTLS {{RFC6347}} to
communicate.  The client uses an access token, bound to a key (the
proof-of-possession key) to authorize its access to protected
resources hosted by the resource server.  DTLS provides communication
security, proof of possession, and server authentication.  Optionally
the client and the resource server may also use CoAP over DTLS to
communicate with the authorization server.  This specification
supports the DTLS handshake with Raw Public Keys (RPK) {{RFC7250}} and
the DTLS handshake with Pre-Shared Keys (PSK) {{RFC4279}}.

The DTLS RPK handshake {{RFC7250}} requires client authentication to
provide proof-of-possession for the key tied to the access token.
Here the access token needs to be transferred to the resource server
before the handshake is initiated, as described in [section 5.8.1 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.8.1).

The DTLS PSK handshake {{RFC4279}} provides the proof-of-possession
for the key tied to the access token.  Furthermore the psk_identity
parameter in the DTLS PSK handshake is used to transfer the access
token from the client to the resource server.

Note: While the scope of this draft is on client and resource server
: communicating using CoAP over DTLS, it is expected that it applies
  also to CoAP over TLS, possibly with minor modifications. However,
  that is out of scope for this version of the draft.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

Readers are expected to be familiar with the terms and concepts
described in {{I-D.ietf-ace-oauth-authz}}.

# Protocol Overview {#overview}

The CoAP-DTLS profile for ACE specifies the transfer of authentication
and, if necessary, authorization information between the client C and
the resource server RS during setup of a DTLS session for CoAP
messaging. It also specifies how a Client can use CoAP over DTLS to
retrieve an Access Token from the authorization server AS for a
protected resource hosted on the resource server RS.

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

To determine the AS in charge of a resource hosted at the RS, the client C MAY
send an initial Unauthorized Resource Request message to the RS. The RS then
denies the request and sends the address of its AS back to the client C.

Once the client C knows the authorization server's address, it can
send an Access Token request to the token endpoint at the AS as
specified in {{I-D.ietf-ace-oauth-authz}}.  If C wants to use the CoAP
RawPublicKey mode as described in [Section 9 of RFC
7252](https://tools.ietf.org/html/rfc7252#section-9) it MUST provide a
key or key identifier within a `cnf` object in the token request.  If
the authorization server AS decides that the request is to be
authorized it generates an access token response for the client C
containing a `profile` parameter with the value `coap_dtls` to
indicate that this profile MUST be used for communication between the
client C and the resource server.  Is also adds a `cnf` parameter with
additional data for the establishment of a secure DTLS channel between
the client and the resource server.  The semantics of the 'cnf'
parameter depend on the type of key used between the client and the
resource server and control whether the client must use RPK mode or
PSK mode to establish a DTLS session with the resource server, see
{{rpk-mode}} and {{psk-mode}}.

The Access Token returned by the authorization server then can be used
by the client to establish a new DTLS session with the resource
server. When the client intends to use asymmetric cryptography in the
DTLS handshake with the resource server, the client MUST upload the
Access Token to the authz-info resource on the resource server before
starting the DTLS handshake, as described in [section 5.8.1 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.8.1).
If only symmetric cryptography is used between the client and the
resource server, the Access Token MAY instead be transferred in the
DTLS ClientKeyExchange message (see {{psk-dtls-channel}}).

{{protocol-overview}} depicts the common protocol flow for the DTLS
profile after the client C has retrieved the Access Token from the
authorization server AS.

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
access-related data between the resource server and the authorization
server so that the authorization server can provide the client and the
resource server with sufficient information to establish a secure
channel, and convey authorization information specific for this
communication relationship to the resource server.

Depending on the desired CoAP security mode, the Client-to-AS request,
AS-to-Client response and DTLS session establishment carry slightly
different information. {{rpk-mode}} addresses the use of raw public
keys while {{psk-mode}} defines how pre-shared keys are used in this
profile.

## Resource Access

Once a DTLS channel has been established as described in {{rpk-mode}}
and {{psk-mode}}, respectively, the client is authorized to access
resources covered by the Access Token it has uploaded to the
authz-info resource hosted by the resource server.

On the resource server side, successful establishment of the DTLS
channel binds the client to the access token, functioning as a
proof-of-possession associated key.  Any request that the resource
server receives on this channel MUST be checked against these
authorization rules that are associated with the identity of the
client.  Incoming CoAP requests that are not authorized with respect
to any Access Token that is associated with the client MUST be
rejected by the resource server with 4.01 response as described in
[Section 5.1.1 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.5.1).

Note: The identity of the client is determined by the authentication process
: during the DTLS handshake. In the asymmetric case, the public key
  will define the client's identity, while in the PSK case, the
  client's identity is defined by the session key generated by the
  authorization server for this communication.

The resource server SHOULD treat an incoming CoAP request as authorized
if the following holds:

1. The message was received on a secure channel that has been
   established using the procedure defined in this document.
1. The authorization information tied to the sending peer is valid.
1. The request is destined for the resource server.
1. The resource URI specified in the request is covered by the
   authorization information.
1. The request method is an authorized action on the resource with
   respect to the authorization information.

Incoming CoAP requests received on a secure DTLS channel MUST be
rejected according to [Section 5.1.1 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.1.1

1. with response code 4.03 (Forbidden) when the resource URI specified
   in the request is not covered by the authorization information, and
1. with response code 4.05 (Method Not Allowed) when the resource URI
   specified in the request covered by the authorization information but
   not the requested action.

The client cannot always know a priori if an Authorized Resource
Request will succeed. If the client repeatedly gets error responses
containing AS Information (cf.  [Section 5.1.1 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.1.1)
as response to its requests, it SHOULD request a new Access Token from
the authorization server in order to continue communication with the
resource server.

## Dynamic Update of Authorization Information {#update}

The client can update the authorization information stored at the
resource server at any time without changing an established DTLS
session. To do so, the Client requests from the authorization server a
new Access Token for the intended action on the respective resource
and uploads this Access Token to the authz-info resource on the
resource server.

{{update-overview}} depicts the message flow where the client C
requests a new Access Token after a security association between the
client and the resource server RS has been established using this
protocol. The token request MUST specify the key identifier of the
existing DTLS channel between the client and the resource server in
the `kid` parameter of the Client-to-AS request. The authorization
server MUST verify that the specified `kid` denotes a valid verifier
for a proof-of-possession ticket that has previously been issued to
the requesting client. Otherwise, the Client-to-AS request MUST be
declined with a the error code `unsupported_pop_key` as defined in
[Section 5.6.3 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.6.3).

When the authorization server issues a new access token to update
existing authorization information it MUST include the specified `kid`
parameter in this access token. A resource server MUST associate the
updated authorization information with any existing DTLS session that
is identified by this key identifier.

Note: By associating the access tokens with the identifier of an
: existing DTLS session, the authorization information can be updated
  without changing the cryptographic keys for the DTLS communication
  between the client and the resource server, i.e. an existing session
  can be used with updated permissions.

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

## Token Expiration {#teardown}

DTLS sessions that have been established in accordance with this
profile are always tied to a specific set of access tokens. As these
tokens may become invalid at any time (either because the token has
expired or the responsible authorization server has revoked the
token), the session may become useless at some point. A resource
server therefore may decide to terminate existing DTLS sessions after
the last valid access token for this session has been deleted.

As specified in [section 5.8.2 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.8.2),
the resource server MUST notify the client with an error response with
code 4.01 (Unauthorized) for any long running request before
terminating the session.

The resource server MAY also keep the session alive for some time and
respond to incoming requests with a 4.01 (Unauthorized) error message
including AS Information to signal that the client needs to upload a
new access token before it can continue using this DTLS session. The
AS Information is created as specified in [section 5.1.2 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.1.2). The
resource server SHOULD add a `kid` parameter to the AS Information
denoting the identifier of the key that it uses internally for this
DTLS session. The client then includes this `kid` parameter in a
Client-to-AS request used to retrieve a new access token to be used
with this DTLS session. In case the key identifier is already known by
the client (e.g. because it was included in the RS Information in an
AS-to-Client response), the `kid` parameter MAY be elided from the AS
Information.

{{as-info-params}} updates Figure 2 in [section 5.1.2 of
draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-08#section-5.1.2)
with the new `kid` parameter in accordance with {{RFC8152}}.


| Parameter name | CBOR Key | Major Type      |
|----------------+----------+-----------------|
| kid            |    4     | 2 (byte string) |
{: #as-info-params title="Updated AS Information parameters"}

# RawPublicKey Mode {#rpk-mode}

To retrieve an access token for the resource that the client wants to
access, the client requests an Access Token from the authorization
server. The client MUST add a `cnf` object carrying either its raw
public key or a unique identifier for a public key that it has
previously made known to the authorization server.

An example Access Token request from the client to the resource server
is depicted in {{rpk-authorization-message-example}}.

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
by the audience string "tempSensor4711" on the authorization server
using a raw public key.

When the authorization server authorizes a request, it will return an
Access Token and a `cnf` object in the AS-to-Client response. Before
the client initiates the DTLS handshake with the resource server, it
MUST send a `POST` request containing the new Access Token to the
authz-info resource hosted by the resource server. If this operation
yields a positive response, the client SHOULD proceed to establish a
new DTLS channel with the resource server. To use raw public key mode,
the client MUST pass the same public key that was used for
constructing the Access Token with the SubjectPublicKeyInfo structure
in the DTLS handshake as specified in {{RFC7250}}.

Note:
: According to {{RFC7252}}, CoAP implementations MUST support the
  ciphersuite TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_CCM\_8 {{RFC7251}}
  and the NIST P-256 curve. the client is therefore expected to offer
  at least this ciphersuite to the resource server.

The Access Token is constructed by the authorization server such that
the resource server can associate the Access Token with the Client's
public key. If CBOR web tokens {{I-D.ietf-ace-cbor-web-token}} are
used as recommended in {{I-D.ietf-ace-oauth-authz}}, the authorization
server MUST include a `COSE_Key` object in the `cnf` claim of the
Access Token. This `COSE_Key` object MAY contain a reference to a key
for the client that is already known by the resource server (e.g.,
from previous communication). If the authorization server has no
certain knowledge that the Client's key is already known to the
resource server, the Client's public key MUST be included in the
Access Token's `cnf` parameter.

# PreSharedKey Mode {#psk-mode}

To retrieve an access token for the resource that the client wants to
access, the client MAY include a `cnf` object carrying an identifier
for a symmetric key in its Access Token request to the authorization
server.  This identifier can be used by the authorization server to
determine the session key to construct the proof-of-possession token
and therefore MUST specify a symmetric key that was previously
generated by the authorization server as a session key for the
communication between the client and the resource server.

Depending on the requested token type and algorithm in the Access
Token request, the authorization server adds RS Information to the
response that provides the client with sufficient information to setup
a DTLS channel with the resource server.  For symmetric
proof-of-possession keys (c.f. {{I-D.ietf-ace-oauth-authz}}), the
client must ensure that the Access Token request is sent over a secure
channel that guarantees authentication, message integrity and
confidentiality.

When the authorization server authorizes the client it returns an
AS-to-Client response with the profile parameter set to `coap_dtls`
and a `cnf` parameter carrying a `COSE_Key` object that contains the
symmetric session key to be used between the client and the resource
server as illustrated in {{at-response}}.

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

In this example, the authorization server returns a 2.01 response
containing a new Access Token.  The information is transferred as a
CBOR data structure as specified in {{I-D.ietf-ace-oauth-authz}}. The
Max-Age option tells the receiving Client how long this token will be
valid.

A response that declines any operation on the requested resource is
constructed according to [Section 5.2 of RFC
6749](https://tools.ietf.org/html/rfc6749#section-5.2), (cf. Section
5.7.3 of {{I-D.ietf-ace-oauth-authz}}).

~~~~~~~~~~
    4.00 Bad Request
    Content-Format: application/cbor
    {
      error: invalid_request
    }
~~~~~~~~~~
{: #token-reject title="Example Access Token response with reject"}

## DTLS Channel Setup Between C and RS {#psk-dtls-channel}

When a client receives an Access Token from an authorization server,
it checks if the payload contains an `access_token` parameter and a
`cnf` parameter. With this information the client can initiate
establishment of a new DTLS channel with a resource server. To use
DTLS with pre-shared keys, the client follows the PSK key exchange
algorithm specified in Section 2 of {{RFC4279}} using the key conveyed
in the `cnf` parameter of the AS response as PSK when constructing the
premaster secret.

In PreSharedKey mode, the knowledge of the session key by the client
and the resource server is used for mutual authentication between both
peers. Therefore, the resource server must be able to determine the
session key from the Access Token. Following the general ACE
authorization framework, the client can upload the Access Token to the
resource server's authz-info resource before starting the DTLS
handshake. Alternatively, the client MAY provide the most recent
Access Token in the `psk_identity` field of the ClientKeyExchange
message. To do so, the client MUST treat the contents of the
`access_token` field from the AS-to-Client response as opaque data and
not perform any re-coding.

Note: As stated in section 4.2 of {{RFC7925}}, the PSK identity should
be treated as binary data in the Internet of Things space and not
assumed to have a human-readable form of any sort.

If a resource server receives a ClientKeyExchange message that
contains a `psk_identity` with a length greater zero, it uses the
contents as index for its key store (i.e., treat the contents as key
identifier). The resource server MUST check if it has one or more
Access Tokens that are associated with the specified key. If no valid
Access Token is available for this key, the DTLS session setup is
terminated with an `illegal_parameter` DTLS alert message.

If no key with a matching identifier is found the resource server the
resource server MAY process the decoded contents of the `psk_identity`
field as access token that is stored with the authorization
information endpoint before continuing the DTLS handshake. If the
decoded contents of the `psk_identity` do not yield a valid access
token for the requesting client, the DTLS session setup is terminated
with an `illegal_parameter` DTLS alert message.

Note1: As a resource server cannot provide a client with a meaningful PSK identity hint in
: response to the client's ClientHello message, the resource server
SHOULD NOT send a ServerKeyExchange message.

Note2:
: According to {{RFC7252}}, CoAP implementations MUST support the
  ciphersuite TLS\_PSK\_WITH\_AES\_128\_CCM\_8 {{RFC6655}}. A client is
  therefore expected to offer at least this ciphersuite to the resource server.

This specification assumes that the Access Token is a PoP token as
described in {{I-D.ietf-ace-oauth-authz}} unless specifically stated
otherwise. Therefore, the Access Token is bound to a symmetric PoP key
that is used as session key between the client and the resource
server.

While the client can retrieve the session key from the contents of the
`cnf` parameter in the AS-to-Client response, the resource server uses
the information contained in the `cnf` claim of the Access Token to
determine the actual session key when no explicit `kid` was provided
in the `psk_identity` field.  Usually, this is done by including a
`COSE_Key` object carrying either a key that has been encrypted with a
shared secret between the authorization server and the resource
server, or a key identifier that can be used by the resource server to
lookup the session key.

Instead of the `COSE_Key` object, the authorization server MAY include
a `COSE_Encrypt` structure to enable the resource server to calculate
the session key from the Access Token. The `COSE_Encrypt` structure
MUST use the *Direct Key with KDF* method as described in [Section
12.1.2 of RFC
8152](https://tools.ietf.org/html/rfc8152#section-12.1.2).  The
authorization server MUST include a Context information structure
carrying a PartyU `nonce` parameter carrying the nonce that has been
used by the authorization server to construct the session key.

This specification mandates that at least the key derivation algorithm
`HKDF SHA-256` as defined in {{RFC8152}} MUST be supported.  This key
derivation function is the default when no `alg` field is included in
the `COSE_Encrypt` structure for the resource server.

## Updating Authorization Information

Usually, the authorization information that the resource server keeps
for a client is updated by uploading a new Access Token as described
in {{update}}.

If the security association with the resource server still exists and
the resource server has indicated support for session renegotiation
according to {{RFC5746}}, the new Access Token MAY be used to
renegotiate the existing DTLS session. In this case, the Access Token
is used as `psk_identity` as defined in {{psk-dtls-channel}}. The
Client MAY also perform a new DTLS handshake according to
{{psk-dtls-channel}} that replaces the existing DTLS session.

After successful completion of the DTLS handshake the resource server
updates the existing authorization information for the client
according to the new Access Token.

# Security Considerations

This document specifies a profile for the Authentication and
Authorization for Constrained Environments (ACE) framework
{{I-D.ietf-ace-oauth-authz}}. As it follows this framework's general
approach, the general security and privacy considerations from section
6 and section 7 also apply to this profile.

Constrained devices that use DTLS {{RFC6347}} are inherently
vulnerable to Denial of Service (DoS) attacks as the handshake
protocol requires creation of internal state within the device.  This
is specifically of concern where an adversary is able to intercept the
initial cookie exchange and interject forged messages with a valid
cookie to continue with the handshake.

{{I-D.tiloca-tls-dos-handshake}} specifies a TLS extension to prevent
this type of attack which is applicable especially for constrained
environments where the authorization server can act as trust anchor.

# Privacy Considerations

An unprotected response to an unauthorized request may disclose
information about the resource server and/or its existing relationship
with the client. It is advisable to include as little information as
possible in an unencrypted response. When a DTLS session between the
client and the resource server already exists, more detailed
information may be included with an error response to provide the
client with sufficient information to react on that particular error.

Note that some information might still leak after DTLS session is
established, due to observable message sizes, the source, and the
destination addresses.

# IANA Considerations

The following registrations are done for the ACE OAuth Profile
Registry following the procedure specified in
{{I-D.ietf-ace-oauth-authz}}.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with
the RFC number of this specification and delete this paragraph.

Profile name: coap_dtls

Profile Description: Profile for delegating client authentication and
authorization in a constrained environment by establishing a Datagram
Transport Layer Security (DTLS) channel between resource-constrained
nodes.

Profile ID:  1

Change Controller:  IESG

Specification Document(s):  {{&SELF}}

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

---
coding: utf-8

title: Datagram Transport Layer Security (DTLS) Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: CoAP-DTLS
docname: draft-ietf-ace-dtls-authorize-latest
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
    org: Ericsson AB
    email: goran.selander@ericsson.com
 -
    ins: L. Seitz
    name: Ludwig Seitz
    org: Combitech
    street: Djäknegatan 31
    city: Malmö
    code: 211 35
    country: Sweden
    email: ludwig.seitz@combitech.se

normative:
  RFC2119:
  RFC8174:
  RFC4279:
  RFC6347:
  RFC6749:
  RFC7250:
  RFC7251:
  RFC7252:
  RFC7925:
  RFC8152:
  RFC8422:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-ace-oauth-params:
  I-D.ietf-ace-cwt-proof-of-possession:

informative:
  RFC5869:
  RFC6655:
  RFC7748:
  RFC8032:
  RFC8392:
  RFC8610:
  RFC8613:
 
entity:
        SELF: "[RFC-XXXX]"

--- abstract

This specification defines a profile of the ACE framework that allows constrained servers
to delegate client authentication and authorization.  The protocol
relies on DTLS for communication security between entities in a
constrained network using either raw public keys or pre-shared keys. A
resource-constrained server can use this protocol to delegate
management of authorization information to a trusted host with less
severe limitations regarding processing power and memory.

--- middle


# Introduction

This specification defines a profile of the ACE framework
{{I-D.ietf-ace-oauth-authz}}.  In this profile, a client and a
resource server use CoAP {{RFC7252}} over DTLS {{RFC6347}} to
communicate. The client obtains an access token, bound to a key
(the proof-of-possession key), from an authorization server to prove
its authorization to access protected resources hosted by the resource
server. Also, the client and the resource server are provided by the
authorization server with the necessary keying material to establish a
DTLS session. The communication between client and authorization server may
also be secured with DTLS.  This specification supports DTLS with Raw
Public Keys (RPK) {{RFC7250}} and with Pre-Shared Keys (PSK)
{{RFC4279}}.

The DTLS handshake requires the client and server to prove
that they can use certain keying material. In the RPK mode, the client
proves with the DTLS handshake that it can use the RPK bound to the
token and the server shows that it can use a certain RPK. The access
token must be presented to the resource server.  For the RPK mode, the
access token needs to be uploaded to the resource server before the
handshake is initiated, as described in
Section 5.8.1 of the ACE framework {{I-D.ietf-ace-oauth-authz}}.

In the PSK mode, client and server show with the DTLS handshake that
they can use the keying material that is bound to the access token.
To transfer the access token from the client to the resource server,
the `psk_identity` parameter in the DTLS PSK handshake may be used
instead of uploading the token prior to the handshake.

As recommended in Section 5.8 of {{I-D.ietf-ace-oauth-authz}}, this
specification uses CBOR web tokens to convey claims within an access
token issued by the server.  While other formats could be used as well,
those are out of scope for this document.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

Readers are expected to be familiar with the terms and concepts
described in {{I-D.ietf-ace-oauth-authz}} and in {{I-D.ietf-ace-oauth-params}}.

The authorization information (authz-info) resource refers to the authorization information endpoint as specified in {{I-D.ietf-ace-oauth-authz}}.

# Protocol Overview {#overview}

The CoAP-DTLS profile for ACE specifies the transfer of authentication
information and, if necessary, authorization information between the
client (C) and
the resource server (RS) during setup of a DTLS session for CoAP
messaging. It also specifies how C can use CoAP over DTLS to
retrieve an access token from the authorization server (AS) for a
protected resource hosted on the resource server.
As specified in Section 6.7 of
{{I-D.ietf-ace-oauth-authz}}, use of DTLS for one or both of these
interactions is completely independent

This profile requires the client to retrieve an access token for protected
resource(s) it wants to access on RS as specified
in {{I-D.ietf-ace-oauth-authz}}. {{at-retrieval}} shows the
typical message flow in this scenario (messages
in square brackets are optional):

~~~~~~~~~~~~~~~~~~~~~~~

   C                                RS                   AS
   | [---- Resource Request ------>]|                     |
   |                                |                     |
   | [<-AS Request Creation Hints-] |                     |
   |                                |                     |
   | ------- Token Request  ----------------------------> |
   |                                |                     |
   | <---------------------------- Access Token --------- |
   |                               + Access Information   |

~~~~~~~~~~~~~~~~~~~~~~~
{: #at-retrieval title="Retrieving an Access Token"}

To determine the AS in charge of a resource hosted at the RS, C can
send an initial Unauthorized Resource Request message to the RS. The RS then
denies the request and sends an AS Request Creation Hints message containing the address
of its AS back to the client as
specified in Section 5.1.2 of {{I-D.ietf-ace-oauth-authz}}.

Once the client knows the authorization server's address, it can
send an access token request to the token endpoint at the AS as
specified in {{I-D.ietf-ace-oauth-authz}}. As the access token request
as well as the response may contain confidential data, the
communication between the client and the authorization server must be
confidentiality-protected and ensure authenticity. C may have been
registered at the AS via the OAuth 2.0 client registration mechanism as
outlined in Section 5.3 of {{I-D.ietf-ace-oauth-authz}}.

The access token returned by the authorization server can then be used
by the client to establish a new DTLS session with the resource
server. When the client intends to use an asymmetric proof-of-possession key in the
DTLS handshake with the resource server, the client MUST upload the
access token to the authz-info resource, i.e. the authz-info endpoint,
on the resource server before
starting the DTLS handshake, as described in Section 5.8.1 of
{{I-D.ietf-ace-oauth-authz}}. In case the client uses a symmetric proof-of-possession
key in the DTLS handshake, the procedure as above MAY be used, or alternatively,
 the access token MAY instead be transferred in the
DTLS ClientKeyExchange message (see {{psk-dtls-channel}}).

{{protocol-overview}} depicts the common protocol flow for the DTLS
profile after the client C has retrieved the access token from the
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

# Protocol Flow

The following sections specify how CoAP is used to interchange
access-related data between the resource server, the client and the
authorization server so that the authorization server can provide the
client and the resource server with sufficient information to
establish a secure channel, and convey authorization information
specific for this communication relationship to the resource server.

{{C-AS-comm}} describes how the communication between C and AS
must be secured.
Depending on the used CoAP security mode (see also
Section 9 of {{RFC7252}},
the Client-to-AS request, AS-to-Client response (see Section
5.6 of {{I-D.ietf-ace-oauth-authz}}) and DTLS session
establishment carry slightly different information. {{rpk-mode}}
addresses the use of raw public keys while {{psk-mode}} defines how
pre-shared keys are used in this profile.

## Communication between C and AS {#C-AS-comm}

To retrieve an access token for the resource that the client wants to
access, the client requests an access token from the authorization
server. Before the client can request the access token, the client and
the authorization server MUST establish
a secure communication channel. This profile assumes that the keying
material to secure this communication channel has securely been obtained
either by manual configuration or in an automated provisioning process.
The following requirements in alignment with Section 6.5 of
{{I-D.ietf-ace-oauth-authz}} therefore must be met:

* The client MUST securely have obtained keying material to communicate
  with AS.
* Furthermore, the client MUST verify that the authorization server is
  authorized to provide access tokens (including authorization
  information) about the resource server to the client.
* Also, the authorization server MUST securely have obtained keying
  material for the client, and obtained authorization rules approved
  by the resource owner (RO) concerning the client and the resource
  server that relate to this keying material.

The client and the authorization server MUST use their respective
keying material for all exchanged messages. How the security
association between the client and the authorization server is
bootstrapped is not part of this document. The client and the
authorization server must ensure the confidentiality, integrity and
authenticity of all exchanged messages within the ACE protocol.

Section {{as-commsec}} specifies how communication with the AS is secured.


## RawPublicKey Mode {#rpk-mode}

When the client and the resource server use RawPublicKey
authentication, the procedure is as follows:
After C and AS mutually authenticated each other and validated each
other's authorization, C sends a token request to AS's token endpoint.
The client MUST add a `req_cnf` object carrying either its raw public key
or a unique identifier for a public key that it has previously made
known to the authorization server. To prove that the client is in
possession of this key, C MUST use the same keying material that it
uses to secure the communication with AS, e.g., the DTLS session.

An example access token request from the client to the AS is depicted
in {{rpk-authorization-message-example}}.

~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: application/ace+cbor
   Payload:
   {
     grant_type : client_credentials,
     req_aud    : "tempSensor4711",
     req_cnf    : {
       COSE_Key : {
         kty : EC2,
         crv : P-256,
         x   : h'e866c35f4c3c81bb96a1...',
         y   : h'2e25556be097c8778a20...'
       }
     }
   }
~~~~~~~~~~
{: #rpk-authorization-message-example title="Access Token Request Example for RPK Mode"}

The example shows an access token request for the resource identified
by the string "tempSensor4711" on the authorization server
using a raw public key.

The AS MUST check if the client that it communicates with is associated
with the RPK in the `req_cnf` parameter before issuing an access token to it.
If the AS determines that the request is to be authorized according to
the respective authorization rules, it generates an access token
response for C. The access token MUST be bound to the RPK of the client 
by means of the `cnf` claim.

The response MAY contain a `profile` parameter with
the value `coap_dtls` to indicate that this profile MUST be used for
communication between the client C and the resource server. The `profile` 
may be specified out-of-band, in which case it does not have to be sent. The
response also contains an access token with
information about the public key that is used by the resource
server. The authorization server MUST return in its response the
parameter `rs_cnf` unless it is certain that the client already knows
the public key of the resource server.
The authorization server MUST ascertain that the RPK specified in `rs_cnf` belongs
to the resource server that the client wants to communicate with. The authorization server MUST
protect the integrity of the access token. If the access token contains
confidential data, the authorization server MUST also protect the confidentiality of the
access token.

The client MUST ascertain that the access token response belongs to a certain
previously sent access token request, as the request may specify the
resource server with which the client wants to communicate.

An example access token response from the authorization to the client
is depicted in {{rpk-authorization-response-example}}. Note that
caching proxies process the Max-Age option in the CoAP response which
has a default value of 60 seconds. The authorization server SHOULD
adjust the Max-Age option such that it does not exceed the
`expires_in` parameter to avoid stale responses.

~~~~~~~~~~
   2.01 Created
   Content-Format: application/ace+cbor
   Max-Age: 3560
   Payload:
   {
     access_token : b64'SlAV32hkKG...
      (remainder of CWT omitted for brevity;
      CWT contains clients RPK in the cnf claim)',
     expires_in : 3600,
     rs_cnf     : {
       COSE_Key : {
         kty : EC2,
         crv : P-256,
         x   : h'd7cc072de2205bdc1537...',
         y   : h'f95e1d4b851a2cc80fff...'
       }
     }
   }
~~~~~~~~~~
{: #rpk-authorization-response-example title="Access Token Response Example for RPK Mode"}

### DTLS Channel Setup Between C and RS {#rpk-dtls-channel}

Before the client initiates the DTLS handshake with the resource
server, C MUST send a `POST` request containing the new access token
to the authz-info resource hosted by the resource server. After the client  
receives a confirmation that the RS has accepted the access token, it 
SHOULD proceed to 
establish a new DTLS channel with the resource server. To use the
RawPublicKey mode, the client MUST specify the public key that AS
defined in the `cnf` field of the access token response in the
SubjectPublicKeyInfo structure in the DTLS handshake as specified in
{{RFC7250}}.

To be consistent with {{RFC7252}} which allows for shortened MAC tags
in constrained environments,
an implementation that supports the RPK mode of this profile MUST at
least support the ciphersuite
TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_CCM\_8 {{RFC7251}}.
As discussed in {{RFC7748}}, new ECC
  curves have been defined recently that are considered superior to
  the so-called NIST curves. This specification therefore mandates
  implementation support for curve25519 (cf. {{RFC8032}}, {{RFC8422}})
  as this curve said to be efficient and less dangerous
  regarding implementation errors than the secp256r1 curve mandated in
  {{RFC7252}}.

RS MUST check if the access token is still valid, if RS is the
intended destination (i.e., the audience) of the token, and if the
token was issued by an authorized AS.
The access token is constructed by the authorization server such that
the resource server can associate the access token with the Client's
public key. 
The `cnf` claim MUST contain either C's RPK or, if the key is already
known by the resource server (e.g., from previous communication),
a reference to this key. If the authorization
server has no
certain knowledge that the Client's key is already known to the
resource server, the Client's public key MUST be included in the
access token's `cnf` parameter. If CBOR web tokens {{RFC8392}} are
used as recommended in
{{I-D.ietf-ace-oauth-authz}}, keys MUST be encoded as specified in
{{I-D.ietf-ace-cwt-proof-of-possession}}.  The resource server MUST use the keying
material that the authorizations server has specified in the `cnf` parameter in
the access token for the DTLS handshake with the client.
Thus, the handshake only finishes if the client and the resource server
are able to use their respective keying material.

## PreSharedKey Mode {#psk-mode}

To retrieve an access token for the resource that the client wants to
access, the client MAY include a `cnf` object carrying an identifier
for a symmetric key in its access token request to the authorization
server.  This identifier can be used by the authorization server to
determine the shared secret to construct the proof-of-possession
token.  The authorization server MUST check if the identifier refers to a symmetric key that was
previously generated by the AS as a shared secret for the
communication between this client and the resource server. If no such
symmetric key was found, the AS MUST generate a new symmetric key that
is returned in its response to the client.

The authorization server MUST determine the authorization rules for
the client it communicates with as defined by the resource owner and generate the access
token accordingly.
If the authorization server authorizes the client, it returns an
AS-to-Client response. If the profile parameter is present, it is set to
`coap_dtls`. AS MUST ascertain that the access token is generated for
the resource server that C wants to communicate with. Also, AS MUST
protect the integrity of the access
token. If the token contains confidential data such as the symmetric
key, the confidentiality of the token MUST also be
protected. Depending on the requested token type and algorithm in the
access token request, the authorization server adds access Information
to the response that provides the client with sufficient information
to setup a DTLS channel with the resource server. AS adds a `cnf`
parameter to the access information carrying a `COSE_Key` object
that informs the client about the symmetric key that is to be used between
C and the resource server. The access token MUST be bound to the same symmetric key
by means of the cnf parameter.

An example access token request for an access token with a symmetric proof-of-possession key is illustrated in {{at-request}}.

~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: application/ace+cbor
   Payload:
   {
     audience    : "smokeSensor1807",
   }
~~~~~~~~~~
{: #at-request title="Example Access Token Request, (implicit) symmetric PoP-key"}

A corresponding example access token response is illustrated in {{at-response}}. 
In this example, the authorization server returns a 2.01 response
containing a new access token and information for the client,
including the symmetric key in the cnf claim.  The information is
transferred as a
CBOR data structure as specified in {{I-D.ietf-ace-oauth-authz}}.


<!-- msg1 -->

~~~~~~~~~~
   2.01 Created
   Content-Format: application/ace+cbor
   Max-Age: 85800
   Payload:
   {
      access_token : h'd08343a10...
      (remainder of CWT omitted for brevity)
      token_type : PoP,
      expires_in : 86400,
      profile    : coap_dtls,
      cnf        : {
        COSE_Key : {
          kty : symmetric,
          kid : h'3d027833fc6267ce',
          k   : h'73657373696f6e6b6579'
        }
      }
   }
~~~~~~~~~~
{: #at-response title="Example Access Token Response, symmetric PoP-key"}

The access token also comprises a `cnf` claim. This claim usually contains a
`COSE_Key` object that carries either the symmetric
key itself or a key identifier that can be used by the resource
server to determine the secret key it shares with the client. If the access token carries a
symmetric key, the access token MUST be encrypted using a `COSE_Encrypt0`
structure. The AS MUST use the keying material shared with the RS to
encrypt the token. 

The `cnf` structure in the access token is provided in {{kdf-cnf}}.

~~~~~~~~~~
cnf : {
  COSE_Key : {
    kty : symmetric,
    kid : h'6549694f464361396c4f6277'
  }
}
~~~~~~~~~~
{: #kdf-cnf title="Access Token without Keying Material"}

A response that declines any operation on the requested resource is
constructed according to Section 5.2 of {{RFC6749}},
(cf. Section 5.6.3. of {{I-D.ietf-ace-oauth-authz}}).

~~~~~~~~~~
    4.00 Bad Request
    Content-Format: application/ace+cbor
    Payload:
    {
      error : invalid_request
    }
~~~~~~~~~~
{: #token-reject title="Example Access Token Response With Reject"}


The method for how the resource server determines the symmetric key from an access token 
containing only a key identifier is application-specific; the remainder of this section 
provides one example. 

The AS and 
the resource server are assumed to share a key derivation key used to derive 
the symmetric key shared with the client from the key identifier in the access token. 
The key derivation key may be derived from some other secret key shared between the AS and the resource server. This key needs
to be securely stored and processed in the same way as the key used to protect the 
communication between AS and RS.

Knowledge of the 
symmetric key shared with the client must not reveal any information about 
the key derivation key or other secret keys shared between AS and resource server.

In order to generate a new symmetric key to be used by client and resource server, 
the AS generates a key identifier and uses the key derivation key shared with the 
resource server to derive the symmetric key as specified below. Instead of 
providing the keying material in the access token, the AS includes the key
identifier in the `kid` parameter, see {{kdf-cnf}}. This key identifier
enables the resource server to calculate the symmetric key used for the 
communication with the client using
the key derivation key and a KDF to be defined by the application, for example
HKDF-SHA-256. The key identifier picked by the AS needs to be unique for each access
token where a unique symmetric key is required.

In this example, HKDF consists of the composition of the HKDF-Extract and HKDF-Expand steps [RFC5869]. The symmetric key is derived from the key identifier, the key derivation key and other data:

OKM = HKDF(salt, IKM, info, L),

where:

* OKM, the output keying material, is the derived symmetric key
* salt is the empty byte string
* IKM, the input keying material, is the key derivation key as defined above
* info is the serialization of a CBOR array consisting of ([RFC8610]):

~~~~~~~~~~~~~~~~~
      info = [
        type : tstr,
        kid : bstr,
        L : uint,
      ]
~~~~~~~~~~~~~~~~~
where:

* type is set to the constant text string "ACE-CoAP-DTLS-key-derivation",
* kid is the key identifier, and
* L is the size of the symmetric key in bytes.


### DTLS Channel Setup Between C and RS {#psk-dtls-channel}

When a client receives an access token response from an authorization
server, C MUST ascertain that the access token response corresponds to a
certain previously sent access token request, as the request may
specify the resource server with which C wants to communicate.

C checks if the payload of the access token response contains an
`access_token` parameter and a
`cnf` parameter. With this information the client can initiate the
establishment of a new DTLS channel with a resource server. To use
DTLS with pre-shared keys, the client follows the PSK key exchange
algorithm specified in Section 2 of {{RFC4279}} using the key conveyed
in the `cnf` parameter of the AS response as PSK when constructing the
premaster secret. To be consistent with the recommendations in
{{RFC7252}} a client is expected to offer at least the
ciphersuite TLS\_PSK\_WITH\_AES\_128\_CCM\_8 {{RFC6655}}
to the resource server.

In PreSharedKey mode, the knowledge of the shared secret by the client
and the resource server is used for mutual authentication between both
peers. Therefore, the resource server must be able to determine the
shared secret from the access token. Following the general ACE
authorization framework, the client can upload the access token to the
resource server's authz-info resource before starting the DTLS
handshake.

As an alternative to the access token upload, the client can provide
the most recent access token in the `psk_identity` field of the
ClientKeyExchange message. To do so, the client MUST treat the
contents of the `access_token` field from the AS-to-Client response as
opaque data as specified in Section 4.2 of [RFC7925] and not perform
any re-coding. This allows the resource server to retrieve the shared
secret directly from the `cnf` claim of the access token.

If a resource server receives a ClientKeyExchange message that
contains a `psk_identity` with a length greater than zero, it MUST
process the contents of the `psk_identity` field as access token that
is stored with the authorization information endpoint, before
continuing the DTLS handshake. If the contents of the `psk_identity`
do not yield a valid access token for the requesting client, the
resource server aborts the DTLS handshake with an `illegal_parameter`
alert.

When RS receives an access token, RS MUST check if the access token is
still valid, if RS is the intended destination (i.e., the audience of
the token), and if the token was issued by an authorized AS.
This specification assumes that the access token is a PoP token as
described in {{I-D.ietf-ace-oauth-authz}} unless specifically stated
otherwise. Therefore, the access token is bound to a symmetric PoP key
that is used as shared secret between the client and the resource
server.

While the client can retrieve the shared secret from the contents of the
`cnf` parameter in the AS-to-Client response, the resource server uses
the information contained in the `cnf` claim of the access token to
determine the actual secret when no explicit `kid` was provided
in the `psk_identity` field. If key derivation is used, the RS uses
the `COSE_KDF_Context` information as described above.

## Resource Access

Once a DTLS channel has been established as described in {{rpk-mode}}
or {{psk-mode}}, respectively, the client is authorized to access
resources covered by the access token it has uploaded to the
authz-info resource hosted by the resource server.

With the successful establishment of the DTLS channel, C and RS have
proven that they can use their respective keying material. An access
token that is bound to the client's keying material is associated
with the channel. According to section 5.8.1 of {{I-D.ietf-ace-oauth-authz}},
there should be only one access token for each client. New access
tokens issued by the authorization server are supposed to replace
previously issued access tokens for the respective client. The resource
server therefore must have a common understanding with the authorization
server how access tokens are ordered.

Any request that the resource server receives on a DTLS channel that
is tied to an access token via its keying material 
MUST be checked against the authorization rules that can be determined
with the access token. The resource server
MUST check for every request if the access token is still valid.
If the token has expired, the resource server MUST remove it.
Incoming CoAP requests that are not authorized with respect
to any access token that is associated with the client MUST be
rejected by the resource server with 4.01 response. The response
MAY include AS Request Creation Hints as described in
Section 5.1.1 of {{I-D.ietf-ace-oauth-authz}}.

The resource server MUST only accept an incoming CoAP request as
authorized if the following holds:

1. The message was received on a secure channel that has been
   established using the procedure defined in this document.
1. The authorization information tied to the sending client is valid.
1. The request is destined for the resource server.
1. The resource URI specified in the request is covered by the
   authorization information.
1. The request method is an authorized action on the resource with
   respect to the authorization information.

Incoming CoAP requests received on a secure DTLS channel that are not
thus authorized MUST be
rejected according to Section 5.8.2 of {{I-D.ietf-ace-oauth-authz}}

1. with response code 4.03 (Forbidden) when the resource URI specified
   in the request is not covered by the authorization information, and
1. with response code 4.05 (Method Not Allowed) when the resource URI
   specified in the request covered by the authorization information but
   not the requested action.

The client MUST ascertain that its keying material is still valid
before sending a request or processing a response.
If the client gets an error response
containing AS Request Creation Hints (cf.  Section 5.1.2 of {{I-D.ietf-ace-oauth-authz}}
as response to its requests, it SHOULD request a new access token from
the authorization server in order to continue communication with the
resource server.

Unauthorized requests that have been received over a DTLS session SHOULD be treated as non-fatal by 
the RS, i.e., the DTLS session SHOULD be kept alive until the associated access token has expired.

# Dynamic Update of Authorization Information {#update}

Resource servers must only use a new access token to update the
authorization information for a DTLS session if the keying material
that is bound to the token is the same that was used in the DTLS
handshake. By associating the access tokens with the identifier of an
existing DTLS session, the authorization information can be updated
without changing the cryptographic keys for the DTLS communication
between the client and the resource server, i.e. an existing session
can be used with updated permissions.

The client can therefore update the authorization information stored at the
resource server at any time without changing an established DTLS
session. To do so, the Client requests a
new access token from the authorization server 
for the intended action on the respective resource
and uploads this access token to the authz-info resource on the
resource server.

{{update-overview}} depicts the message flow where the C
requests a new access token after a security association between the
client and the resource server has been established using this
protocol. If the client wants to update the authorization information,
the token request MUST specify the key identifier of the proof-of-possession 
key used for the
existing DTLS channel between the client and the resource server in
the `kid` parameter of the Client-to-AS request. The authorization
server MUST verify that the specified `kid` denotes a valid verifier
for a proof-of-possession token that has previously been issued to
the requesting client. Otherwise, the Client-to-AS request MUST be
declined with the error code `unsupported_pop_key` as defined in
Section 5.6.3 of {{I-D.ietf-ace-oauth-authz}}.

When the authorization server issues a new access token to update
existing authorization information, it MUST include the specified `kid`
parameter in this access token. A resource server MUST replace the
authorization information of any existing DTLS session that is identified
by this key identifier with the updated authorization information.

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                   AS
   | <===== DTLS channel =====> |                     |
   |        + Access Token      |                     |
   |                            |                     |
   | --- Token Request  ----------------------------> |
   |                            |                     |
   | <---------------------------- New Access Token - |
   |                           + Access Information   |
   |                            |                     |
   | --- Update /authz-info --> |                     |
   |     New Access Token       |                     |
   |                            |                     |
   | == Authorized Request ===> |                     |
   |                            |                     |
   | <=== Protected Resource == |                     |

~~~~~~~~~~~~~~~~~~~~~~~
{: #update-overview title="Overview of Dynamic Update Operation"}

# Token Expiration {#teardown}

The resource server MUST delete access tokens that are no longer
valid.  DTLS associations that have been setup in accordance with
this profile are always tied to specific tokens (which may be
exchanged with a dynamic update as described in Section 4). As tokens
may become invalid at any time (e.g. because they have expired), the
association may become useless at some point.  A resource server therefore
MUST terminate existing DTLS association after the last access token
associated with this association has expired.

As specified in Section 5.8.3 of {{I-D.ietf-ace-oauth-authz}},
the resource server MUST notify the client with an error response with
code 4.01 (Unauthorized) for any long running request before
terminating the association.

# Secure Communication with AS {#as-commsec}

As specified in the ACE framework (sections 5.6 and 5.7 of
{{I-D.ietf-ace-oauth-authz}}), the requesting entity (RS and/or client)
and the AS communicate via the token endpoint or introspection endpoint.  The
use of CoAP and DTLS for this communication is RECOMMENDED in this
profile, other protocols (such as HTTP and TLS, or CoAP and OSCORE {{RFC8613}}) MAY be used
instead.

How credentials (e.g., PSK, RPK, X.509 cert) for using DTLS with the AS are established is out of scope for this profile.

If other means of securing the communication with the AS are used, the
communication security requirements from Section 6.2 of
{{I-D.ietf-ace-oauth-authz}} remain applicable.

# Security Considerations

This document specifies a profile for the Authentication and
Authorization for Constrained Environments (ACE) framework
{{I-D.ietf-ace-oauth-authz}}. As it follows this framework's general
approach, the general security considerations from section
6 also apply to this profile.

The authorization server must ascertain that the keying material for
the client that it provides to the resource server actually is
associated with this client.  Malicious clients may hand over access
tokens containing their own access permissions to other entities. This
problem cannot be completely eliminated. Nevertheless, in RPK mode it
should not be possible for clients to request access tokens for
arbitrary public keys, since that would allow the client to relay
tokens without the need to share its own credentials with others. The
authorization server therefore should at some point validate that the
client can actually use the private key corresponding to the client's
public key.

When using pre-shared keys provisioned by the AS, the security level depends on the randomness of PSK, and the security of the TLS cipher suite and key exchange algorithm.

The PSK mode of this profile offers a distribution mechanism to convey
authorization tokens together with a shared secret to a client and a
server. As this specification aims at constrained devices and uses
CoAP [RFC7252] as transfer protocol, at least the ciphersuite
TLS\_PSK\_WITH\_AES\_128\_CCM\_8 {{RFC6655}} should be supported. The
access tokens and the corresponding shared secrets generated by the
authorization server are expected to be sufficiently short-lived to
provide similar forward-secrecy properties to using ephemeral
Diffie-Hellman (DHE) key exchange mechanisms. For longer-lived access
tokens, DHE ciphersuites should be used.

Constrained devices that use DTLS {{RFC6347}} are inherently
vulnerable to Denial of Service (DoS) attacks as the handshake
protocol requires creation of internal state within the device.  This
is specifically of concern where an adversary is able to intercept the
initial cookie exchange and interject forged messages with a valid
cookie to continue with the handshake. A similar issue exists with
the authorization information endpoint where the resource server
needs to keep valid access tokens until their expiry. Adversaries can fill
up the constrained resource server's internal storage for a very
long time with interjected or otherwise retrieved valid access tokens.

The use of multiple access tokens for a single client increases the
strain on the resource server as it must consider every access token
and calculate the actual permissions of the client. Also, tokens may
contradict each other which may lead the server to enforce wrong
permissions. If one of the access tokens expires earlier than others,
the resulting permissions may offer insufficient
protection. Developers SHOULD avoid using multiple access
tokens for a client.

# Privacy Considerations

This privacy considerations from section
7 of the {{I-D.ietf-ace-oauth-authz}} apply also to this profile.

An unprotected response to an unauthorized request may disclose
information about the resource server and/or its existing relationship
with the client. It is advisable to include as little information as
possible in an unencrypted response. When a DTLS session between a known
client and the resource server already exists, more detailed
information MAY be included with an error response to provide the
client with sufficient information to react on that particular error.

Also, unprotected requests to the resource server may reveal
information about the client, e.g., which resources the client
attempts to request or the data that the client wants to provide to
the resource server. The client SHOULD NOT send confidential data in
an unprotected request.

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

Profile ID:  TBD (suggested: 1)

Change Controller:  IESG

Reference:  {{&SELF}}

# Acknowledgments

Thanks to Jim Schaad for his contributions and reviews of this
document. Special thanks to Ben Kaduk for his thorough review of this
document.

Ludwig Seitz worked on this document as part of the CelticNext
projects CyberWI, and CRITISEC with funding from Vinnova.

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

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/erlang/charlist.{type Charlist}
import gleam/http.{type Method}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/list
import gleam/result
import gleam/uri

pub type HttpError {
  /// The response body contained non-UTF-8 data, but UTF-8 data was expected.
  InvalidUtf8Response
  /// It was not possible to connect to the host.
  FailedToConnect(ip4: ConnectError, ip6: ConnectError)
  /// The response was not received within the configured timeout period.
  ResponseTimeout
  /// Failed to parce CA certificate
  InvalidCACertificate
  /// Failed to parse client certificate
  InvalidClientCertificate
  /// Failed to parse client Key
  InvalidClientKey
}

pub type ConnectError {
  Posix(code: String)
  TlsAlert(code: String, detail: String)
}

@external(erlang, "gleam_httpc_ffi", "default_user_agent")
fn default_user_agent() -> #(Charlist, Charlist)

@external(erlang, "gleam_httpc_ffi", "normalise_error")
fn normalise_error(error: Dynamic) -> HttpError

@external(erlang, "gleam_httpc_ffi", "pem_to_der")
fn pem_to_der(pem: String) -> BitArray

@external(erlang, "gleam_httpc_ffi", "pem_key_decode")
fn pem_key_decode(pem: String) -> BitArray

type ErlHttpOption {
  Ssl(List(ErlSslOption))
  Autoredirect(Bool)
  Timeout(Int)
}

/// TLS Verification options for HTTPS connections
pub type TlsVerification {
  NoVerification
  VerifyWithSystemCAs
  VerifyWithCustomCA(cacert: BitArray)
}

/// Client Certificate options for mTLS authentication
pub type ClientCert {
  NoClientCert
  ClientCert(cert: BitArray, key: BitArray)
}

type BodyFormat {
  Binary
}

type ErlOption {
  BodyFormat(BodyFormat)
  SocketOpts(List(SocketOpt))
}

type SocketOpt {
  Ipfamily(Inet6fb4)
}

type Inet6fb4 {
  Inet6fb4
}

type ErlSslOption {
  Verify(ErlVerifyOption)
  Cacerts(BitArray)
  Cert(BitArray)
  Key(BitArray)
}

type ErlVerifyOption {
  VerifyNone
}

@external(erlang, "httpc", "request")
fn erl_request(
  a: Method,
  b: #(Charlist, List(#(Charlist, Charlist)), Charlist, BitArray),
  c: List(ErlHttpOption),
  d: List(ErlOption),
) -> Result(
  #(#(Charlist, Int, Charlist), List(#(Charlist, Charlist)), BitArray),
  Dynamic,
)

@external(erlang, "httpc", "request")
fn erl_request_no_body(
  a: Method,
  b: #(Charlist, List(#(Charlist, Charlist))),
  c: List(ErlHttpOption),
  d: List(ErlOption),
) -> Result(
  #(#(Charlist, Int, Charlist), List(#(Charlist, Charlist)), BitArray),
  Dynamic,
)

fn string_header(header: #(Charlist, Charlist)) -> #(String, String) {
  let #(k, v) = header
  #(charlist.to_string(k), charlist.to_string(v))
}

// TODO: refine error type
/// Send a HTTP request of binary data using the default configuration.
///
/// If you wish to use some other configuration use `dispatch_bits` instead.
///
pub fn send_bits(
  req: Request(BitArray),
) -> Result(Response(BitArray), HttpError) {
  configure()
  |> dispatch_bits(req)
}

// TODO: refine error type
/// Send a HTTP request of binary data.
///
pub fn dispatch_bits(
  config: Configuration,
  req: Request(BitArray),
) -> Result(Response(BitArray), HttpError) {
  let erl_url =
    req
    |> request.to_uri
    |> uri.to_string
    |> charlist.from_string
  let erl_headers = prepare_headers(req.headers)
  let erl_http_options = [
    Autoredirect(config.follow_redirects),
    Timeout(config.timeout),
  ]
  let ssl_opts = case config.verify_tls {
    NoVerification -> [Verify(VerifyNone)]
    VerifyWithSystemCAs -> []
    VerifyWithCustomCA(cacert) -> [Cacerts(pem_to_der(cacert))]
  }

  let ssl_opts = case config.client_cert {
    NoClientCert -> ssl_opts
    ClientCert(cert, key) -> [
      Cert(pem_to_der(cert)),
      Key(pem_key_decode(key)),
      ..ssl_opts
    ]
  }

  let erl_http_options = case ssl_opts {
    [] -> erl_http_options
    _ -> [Ssl(ssl_opts), ..erl_http_options]
  }

  let erl_options = [BodyFormat(Binary), SocketOpts([Ipfamily(Inet6fb4)])]

  use response <- result.try(
    case req.method {
      http.Options | http.Head | http.Get -> {
        let erl_req = #(erl_url, erl_headers)
        erl_request_no_body(req.method, erl_req, erl_http_options, erl_options)
      }
      _ -> {
        let erl_content_type =
          req
          |> request.get_header("content-type")
          |> result.unwrap("application/octet-stream")
          |> charlist.from_string
        let erl_req = #(erl_url, erl_headers, erl_content_type, req.body)
        erl_request(req.method, erl_req, erl_http_options, erl_options)
      }
    }
    |> result.map_error(normalise_error),
  )

  let #(#(_version, status, _status), headers, resp_body) = response
  Ok(Response(status, list.map(headers, string_header), resp_body))
}

/// Configuration that can be used to send HTTP requests.
///
/// To be used with `dispatch` and `dispatch_bits`.
///
pub opaque type Configuration {
  Builder(
    /// Whether to verify the TLS certificate of the server.
    ///
    /// This defaults to `True`, meaning that the TLS certificate will be verified
    /// unless you call this function with `False`.
    ///
    /// Setting this to `False` can make your application vulnerable to
    /// man-in-the-middle attacks and other security risks. Do not do this unless
    /// you are sure and you understand the risks.
    ///
    verify_tls: TlsVerification,
    /// Client Certs for mTLS
    ///
    client_cert: ClientCert,
    /// Whether to follow redirects.
    ///
    follow_redirects: Bool,
    /// Timeout for the request in milliseconds.
    ///
    timeout: Int,
  )
}

/// Create a new configuration with the default settings.
///
/// # Defaults
///
/// - TLS is verified using system CAs.
/// - No client certificate (no mTLS).
/// - Redirects are not followed.
/// - The timeout for the response to be received is 30 seconds from when the
///   request is sent.
///
pub fn configure() -> Configuration {
  Builder(
    verify_tls: VerifyWithSystemCAs,
    client_cert: NoClientCert,
    follow_redirects: False,
    timeout: 30_000,
  )
}

/// Set whether to verify the TLS certificate of the server.
///
/// This defaults to `True`, meaning that the TLS certificate will be verified
/// unless you call this function with `False`.
///
/// Setting this to `False` can make your application vulnerable to
/// man-in-the-middle attacks and other security risks. Do not do this unless
/// you are sure and you understand the risks.
///
@deprecated("Use with_tls_verification/2 instead")
pub fn verify_tls(config: Configuration, which: Bool) -> Configuration {
  let mode = case which {
    True -> VerifyWithSystemCAs
    False -> NoVerification
  }
  Builder(..config, verify_tls: mode)
}

/// New function accepting all verification modes
pub fn with_tls_verification(
  config: Configuration,
  mode: TlsVerification
) -> Configuration {
  Builder(..config, verify_tls: mode)
}

/// New function accepting client cert mTLS
pub fn with_client_cert(
  config: Configuration,
  cert: ClientCert
) -> Configuration {
  Builder(..config, client_cert: cert)
}

/// Set whether redirects should be followed automatically.
pub fn follow_redirects(config: Configuration, which: Bool) -> Configuration {
  Builder(..config, follow_redirects: which)
}

/// Set the timeout in milliseconds, the default being 30 seconds.
///
/// If the response is not recieved within this amount of time then the
/// client disconnects and an error is returned.
///
pub fn timeout(config: Configuration, timeout: Int) -> Configuration {
  Builder(..config, timeout:)
}

/// Send a HTTP request of unicode data.
///
pub fn dispatch(
  config: Configuration,
  request: Request(String),
) -> Result(Response(String), HttpError) {
  let request = request.map(request, bit_array.from_string)
  use resp <- result.try(dispatch_bits(config, request))

  case bit_array.to_string(resp.body) {
    Ok(body) -> Ok(response.set_body(resp, body))
    Error(_) -> Error(InvalidUtf8Response)
  }
}

// TODO: refine error type
/// Send a HTTP request of unicode data using the default configuration.
///
/// If you wish to use some other configuration use `dispatch` instead.
///
pub fn send(req: Request(String)) -> Result(Response(String), HttpError) {
  configure()
  |> dispatch(req)
}

fn prepare_headers(
  headers: List(#(String, String)),
) -> List(#(Charlist, Charlist)) {
  prepare_headers_loop(headers, [], False)
}

fn prepare_headers_loop(
  in: List(#(String, String)),
  out: List(#(Charlist, Charlist)),
  user_agent_set: Bool,
) -> List(#(Charlist, Charlist)) {
  case in {
    [] if user_agent_set -> out
    [] -> [default_user_agent(), ..out]
    [#(k, v), ..in] -> {
      let user_agent_set = user_agent_set || k == "user-agent"
      let out = [#(charlist.from_string(k), charlist.from_string(v)), ..out]
      prepare_headers_loop(in, out, user_agent_set)
    }
  }
}

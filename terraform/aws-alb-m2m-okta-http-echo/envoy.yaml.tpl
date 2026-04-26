# =============================================================================
# envoy.yaml.tpl
#
# Envoy sidecar configuration for the main ECS task (http-echo + envoy).
#
# In the air-gapped setup the task has NO direct internet egress.
# Okta-bound calls (JWKS fetch for JWT validation) are tunnelled via HTTP
# CONNECT through the envoy-gateway container, which is the only path to the
# public internet.
#
# The gateway is discovered via ECS Service Connect DNS: the name "envoy-gateway"
# resolves to the gateway task ENI within the same cluster namespace.
#
# Template variables (filled by Terraform templatefile()):
#   ${okta_issuer}  – e.g. "https://dev-12345.okta.com/oauth2/default"
#   ${okta_domain}  – e.g. "dev-12345.okta.com"
# =============================================================================

static_resources:

  listeners:
  # -------------------------------------------------------------------------
  # Listener: M2M API proxy on port 4180
  # Authenticates JWT tokens issued by Okta before forwarding to http-echo.
  # -------------------------------------------------------------------------
  - name: listener_api
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 4180
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: local_http_echo
          http_filters:
          - name: envoy.filters.http.jwt_authn
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
              providers:
                okta:
                  issuer: "${okta_issuer}"
                  claim_to_headers:
                  - header_name: "x-okta-scope"
                    claim_name: "scp"
                  - header_name: "x-okta-client-id"
                    claim_name: "cid"
                  remote_jwks:
                    http_uri:
                      # Envoy fetches the JWKS via the gateway forward proxy
                      # (HTTP CONNECT tunnel → port 3128 on envoy-gateway)
                      uri: "${okta_issuer}/v1/keys"
                      cluster: okta_jwks_cluster
                      timeout: 10s
                    cache_duration:
                      seconds: 300
              rules:
              - match:
                  path: "/ping"   # health-check: no auth required
              - match:
                  prefix: "/"
                requires:
                  provider_name: okta
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  # -------------------------------------------------------------------------
  # Clusters
  # -------------------------------------------------------------------------
  clusters:

  # Local http-echo container (sidecar, same task)
  - name: local_http_echo
    connect_timeout: 1s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: local_http_echo
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 8080

  # Okta JWKS cluster — traffic is tunnelled via the envoy-gateway forward proxy.
  # Envoy uses HTTP CONNECT to establish a tunnel to okta_domain:443 through
  # the gateway (which sits in the gateway subnet with NAT internet access).
  - name: okta_jwks_cluster
    connect_timeout: 10s
    type: STRICT_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    # The actual upstream TLS session is to Okta; Envoy wraps it inside the
    # CONNECT tunnel so the gateway sees an opaque encrypted stream.
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: "${okta_domain}"
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: /etc/ssl/certs/ca-certificates.crt
    # Tunnel through the envoy-gateway forward proxy (HTTP CONNECT)
    upstream_http_protocol_options:
      accept_http_10: true
    http_protocol_options: {}
    # Proxy the connection through the envoy-gateway container
    # The gateway address is injected at ECS task launch time via the
    # ENVOY_GATEWAY_HOST environment variable (see ecs.tf).
    load_assignment:
      cluster_name: okta_jwks_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                # ECS Service Connect DNS name for the envoy-gateway service.
                # Within the Service Connect namespace the gateway registers
                # itself simply as "envoy-gateway" on port 3128.
                address: "envoy-gateway"
                port_value: 3128

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9902

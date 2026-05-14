# =============================================================================
# envoy.yaml.tpl
#
# Envoy sidecar configuration for the main ECS task (http-echo + envoy).
#
# In this architecture, egress traffic (like fetching JWKS from Okta) is
# routed via the Transit Gateway to a centralized Firewall VPC for inspection,
# and then to an Egress VPC with NAT Gateways for internet access.
#
# No local forward proxy is required; standard egress routing handles it.
#
# Template variables:
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
                      uri: "${okta_issuer}/v1/keys"
                      cluster: okta_jwks_cluster
                      timeout: 5s
                    cache_duration:
                      seconds: 300
              rules:
              - match:
                  path: "/ping"
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

  # Local http-echo container
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

  # Okta JWKS cluster — direct egress (routed via TGW/FW/NAT)
  - name: okta_jwks_cluster
    connect_timeout: 5s
    type: STRICT_DNS
    load_assignment:
      cluster_name: okta_jwks_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: "${okta_domain}"
                port_value: 443
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: "${okta_domain}"
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: /etc/ssl/certs/ca-certificates.crt

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9902

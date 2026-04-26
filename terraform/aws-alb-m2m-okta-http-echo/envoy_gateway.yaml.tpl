# =============================================================================
# envoy_gateway.yaml.tpl
#
# Envoy configuration for the *standalone* envoy-gateway container.
# Role: Internet network firewall / egress gateway.
#
# The main task's envoy sidecar sends its Okta API calls (JWKS fetch,
# token introspection, etc.) through this proxy via HTTP CONNECT tunnelling
# on port 3128.  Envoy enforces an allowlist so only traffic destined for
# the Okta domain can be proxied out; any other destination is rejected with
# a 403.
#
# Template variables (filled by Terraform templatefile()):
#   ${okta_domain}  – e.g. "dev-12345678.okta.com"
# =============================================================================

static_resources:

  listeners:
  # -------------------------------------------------------------------------
  # Listener: Forward-proxy on port 3128
  # Accepts HTTP CONNECT requests from the main ECS task's envoy sidecar.
  # -------------------------------------------------------------------------
  - name: forward_proxy_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 3128
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: egress_proxy
          upgrade_configs:
          - upgrade_type: CONNECT   # Enable HTTP CONNECT tunnelling
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                text_format_source:
                  inline_string: |
                    [GATEWAY] %START_TIME% %REQ(:METHOD)% %REQ(HOST)% %REQ(:PATH)% -> status=%RESPONSE_CODE% flags=%RESPONSE_FLAGS% duration=%DURATION%ms
          route_config:
            name: proxy_route
            virtual_hosts:
            # ------------------------------------------------------------------
            # ALLOWLIST: Only the Okta domain is permitted.
            # Any other Host header → 403 Forbidden.
            # ------------------------------------------------------------------
            - name: okta_allowed
              domains:
                - "${okta_domain}"
                - "${okta_domain}:443"
              routes:
              - match:
                  connect_matcher: {}
                route:
                  cluster: okta_upstream
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {}
              - match:
                  prefix: "/"
                route:
                  cluster: okta_upstream

            # Catch-all: block everything else
            - name: deny_all
              domains:
                - "*"
              routes:
              - match:
                  prefix: "/"
                direct_response:
                  status: 403
                  body:
                    inline_string: "Forbidden: only Okta endpoints are allowed through this gateway.\n"
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  # -------------------------------------------------------------------------
  # Clusters
  # -------------------------------------------------------------------------
  clusters:
  - name: okta_upstream
    connect_timeout: 10s
    type: STRICT_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: "${okta_domain}"
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: /etc/ssl/certs/ca-certificates.crt   # Verify Okta's cert
    load_assignment:
      cluster_name: okta_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: "${okta_domain}"
                port_value: 443

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901

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
            - name: okta_allowed
              domains:
                - "${okta_domain}"
                - "${okta_domain}:443"
              routes:
              - match:
                  connect_matcher: {}
                route:
                  cluster: dynamic_forward_proxy_cluster
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {}
              - match:
                  prefix: "/"
                route:
                  cluster: dynamic_forward_proxy_cluster

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
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache_config
                dns_lookup_family: V4_ONLY
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  # -------------------------------------------------------------------------
  # Clusters
  # -------------------------------------------------------------------------
  clusters:
  - name: dynamic_forward_proxy_cluster
    connect_timeout: 10s
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: dynamic_forward_proxy_cache_config
          dns_lookup_family: V4_ONLY

admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901

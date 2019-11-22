# These are the diffs for my branch from our copy of kubespray v2.7.0

See `git diff origin/v2.7.0`

```
diff --git a/roles/download/defaults/main.yml b/roles/download/defaults/main.yml
index 99f9203..7ef5b95 100644
--- a/roles/download/defaults/main.yml
+++ b/roles/download/defaults/main.yml
@@ -39,6 +39,10 @@ kube_version: v1.11.3
 kubeadm_version: "{{ kube_version }}"
 etcd_version: v3.2.18
 
+# gcr and kubernetes image repo define
+gcr_image_repo: "gcr.io"
+kube_image_repo: "{{ gcr_image_repo }}/google-containers"
+
 # TODO(mattymo): Move calico versions to roles/network_plugins/calico/defaults
 # after migration to container download
 calico_version: "v3.1.3"
@@ -94,12 +98,12 @@ kubeadm_checksums:
   v1.16.0: 18f30d65fb05148c73cc07c77a83f4a2427379af493ca9f60eda42239409e7ef
   v1.15.4: 3acf748ec5d69f316da85fb1e75945afb028f1e207ecb0b5986e23932c040194
   v1.15.3: ec56a00bc8d9ec4ac2b081a3b2127d8593daf3b2c86560cf9e6cba5ada2d5a80
-  v1.14.1: 8e548f0724da5bf115d25c2667357feacd73679ecf13d142bdc04f0c376d7c30
+  v1.14.1: c4fc478572b5623857f5d820e1c107ae02049ca02cf2993e512a091a0196957b
   v1.14.0: 03678f49ee4737f8b8c4f59ace0d140a36ffbc4f6035c59561f59f45b57d0c93
-  v1.13.10: 274bf887039a9993e30f96047a4a474c39e8471c4094acb75aea6beed793f079
+  v1.13.10: caa13e911139dcb0c9c3fdefc034f9c6d347655e12c8f80055a5d0345b49626a
   v1.13.6: 274bf887039a9993e30f96047a4a474c39e8471c4094acb75aea6beed793f079
   v1.13.5: 274bf887039a9993e30f96047a4a474c39e8471c4094acb75aea6beed793f079
-  v1.12.9: 463fb058b7fa2591fb01f29f2451b054f6cbaa0f8a20394b4a4eb5d68473176f
+  v1.12.9: 1a9af588d3514d1ccf3c4027e71bdad412a020f51f4a99cc926ce5ff9f13e87a
   v1.12.0: 463fb058b7fa2591fb01f29f2451b054f6cbaa0f8a20394b4a4eb5d68473176f
   v1.11.9: 750edf46d70546e1bee4adf4a59411aa0f7990ccd3c0737fb961820c592a8f34
   v1.11.3: 422a7a32ed9a7b1eaa2a4f9d121674dfbe80eb41e206092c13017d097f75aaec

diff --git a/roles/kubernetes/kubeadm/defaults/main.yml b/roles/kubernetes/kubeadm/defaults/main.yml
index d9ed537..7bdb702 100644
--- a/roles/kubernetes/kubeadm/defaults/main.yml
+++ b/roles/kubernetes/kubeadm/defaults/main.yml
@@ -1,3 +1,14 @@
 ---
 # discovery_timeout modifies the discovery timeout
 discovery_timeout: 5m0s
+kubeadm_join_timeout: 120s
+
+# Optionally remove kube_proxy installed by kubeadm
+kube_proxy_remove: false
+
+# If non-empty, will use this string as identification instead of the actual hostname
+kube_override_hostname: >-
+  {%- if cloud_provider is defined and cloud_provider in [ 'aws' ] -%}
+  {%- else -%}
+  {{ inventory_hostname }}
+  {%- endif -%}

diff --git a/roles/kubernetes/kubeadm/tasks/main.yml b/roles/kubernetes/kubeadm/tasks/main.yml
index 6c4dbe5..46cb5cf 100644
--- a/roles/kubernetes/kubeadm/tasks/main.yml
+++ b/roles/kubernetes/kubeadm/tasks/main.yml
@@ -41,6 +41,11 @@
     kubeadmConfig_api_version: v1alpha2
   when: kubeadm_output.stdout|version_compare('v1.11.0', '>=')
 
+- name: defaults kubeadm api version to v1beta1
+  set_fact:
+    kubeadmConfig_api_version: v1beta1
+  when: kubeadm_output.stdout|version_compare('v1.13.0', '>=')
+
 - name: Create kubeadm client config
   template:
     src: "kubeadm-client.conf.{{ kubeadmConfig_api_version }}.j2"

diff --git a/roles/kubernetes/kubeadm/templates/kubeadm-client.conf.v1beta1.j2 b/roles/kubernetes/kubeadm/templates/kubeadm-client.conf.v1beta1.j2
new file mode 100644
index 0000000..36cc01f
--- /dev/null
+++ b/roles/kubernetes/kubeadm/templates/kubeadm-client.conf.v1beta1.j2
@@ -0,0 +1,23 @@
+apiVersion: kubeadm.k8s.io/v1beta1
+kind: JoinConfiguration
+discovery:
+  bootstrapToken:
+{% if kubeadm_config_api_fqdn is defined %}
+    apiServerEndpoint: {{ kubeadm_config_api_fqdn }}:{{ loadbalancer_apiserver.port | default(kube_apiserver_port) }}
+{% else %}
+    apiServerEndpoint: {{ kubeadm_discovery_address | replace("https://", "")}}
+{% endif %}
+    token: {{ kubeadm_token }}
+    unsafeSkipCAVerification: true
+  timeout: {{ discovery_timeout }}
+  tlsBootstrapToken: {{ kubeadm_token }}
+caCertPath: {{ kube_cert_dir }}/ca.crt
+nodeRegistration:
+  name: {{ kube_override_hostname }}
+{% if container_manager == 'crio' %}
+  criSocket: /var/run/crio/crio.sock
+{% elif container_manager == 'rkt' %}
+  criSocket: /var/run/rkt.sock
+{% else %}
+  criSocket: /var/run/dockershim.sock
+{% endif %}

diff --git a/roles/kubernetes/master/defaults/main.yml b/roles/kubernetes/master/defaults/main.yml
index 49a09e2..28b47ed 100644
--- a/roles/kubernetes/master/defaults/main.yml
+++ b/roles/kubernetes/master/defaults/main.yml
@@ -24,6 +24,11 @@ kube_apiserver_storage_backend: etcd3
 # By default, force back to etcd2. Set to true to force etcd3 (experimental!)
 force_etcd3: false
 
+# Associated interfaces must be reachable by the rest of the cluster, and by
+# CLI/web clients.
+kube_controller_manager_bind_address: 0.0.0.0
+kube_scheduler_bind_address: 0.0.0.0
+
 # audit support
 kubernetes_audit: false
 # path to audit log file
@@ -129,6 +134,16 @@ kube_kubeadm_apiserver_extra_args: {}
 kube_kubeadm_controller_extra_args: {}
 kube_kubeadm_scheduler_extra_args: {}
 
+## Extra control plane host volume mounts
+## Example:
+# apiserver_extra_volumes:
+#  - name: name
+#    hostPath: /host/path
+#    mountPath: /mount/path
+#    readOnly: true
+apiserver_extra_volumes: {}
+controller_manager_extra_volumes: {}
+scheduler_extra_volumes: {}
 ## Encrypting Secret Data at Rest
 kube_encrypt_secret_data: false
 kube_encrypt_token: "{{ lookup('password', credentials_dir + '/kube_encrypt_token.creds length=32 chars=ascii_letters,digits') }}"
@@ -137,3 +152,122 @@ kube_encryption_algorithm: "aescbc"
 
 # You may want to use ca.pem depending on your situation
 kube_front_proxy_ca: "front-proxy-ca.pem"
+
+# included from main/kube-proxy.yaml (from Kubespray v2.9.0)
+
+# bind address for kube-proxy
+kube_proxy_bind_address: '0.0.0.0'
+
+# acceptContentTypes defines the Accept header sent by clients when connecting to a server, overriding the
+# default value of 'application/json'. This field will control all connections to the server used by a particular
+# client.
+kube_proxy_client_accept_content_types: ''
+
+# burst allows extra queries to accumulate when a client is exceeding its rate.
+kube_proxy_client_burst: 10
+
+# contentType is the content type used when sending data to the server from this client.
+kube_proxy_client_content_type: application/vnd.kubernetes.protobuf
+
+# kubeconfig is the path to a KubeConfig file.
+# Leave as empty string to generate from other fields
+kube_proxy_client_kubeconfig: ''
+
+# qps controls the number of queries per second allowed for this connection.
+kube_proxy_client_qps: 5
+
+# How often configuration from the apiserver is refreshed. Must be greater than 0.
+kube_proxy_config_sync_period: 15m0s
+
+### Conntrack
+# max is the maximum number of NAT connections to track (0 to
+# leave as-is).  This takes precedence over maxPerCore and min.
+kube_proxy_conntrack_max: 'null'
+
+# maxPerCore is the maximum number of NAT connections to track
+# per CPU core (0 to leave the limit as-is and ignore min).
+kube_proxy_conntrack_max_per_core: 32768
+
+# min is the minimum value of connect-tracking records to allocate,
+# regardless of conntrackMaxPerCore (set maxPerCore=0 to leave the limit as-is).
+kube_proxy_conntrack_min: 131072
+
+# tcpCloseWaitTimeout is how long an idle conntrack entry
+# in CLOSE_WAIT state will remain in the conntrack
+# table. (e.g. '60s'). Must be greater than 0 to set.
+kube_proxy_conntrack_tcp_close_wait_timeout: 1h0m0s
+
+# tcpEstablishedTimeout is how long an idle TCP connection will be kept open
+# (e.g. '2s').  Must be greater than 0 to set.
+kube_proxy_conntrack_tcp_established_timeout: 24h0m0s
+
+# Enables profiling via web interface on /debug/pprof handler.
+# Profiling handlers will be handled by metrics server.
+kube_proxy_enable_profiling: false
+
+# bind address for kube-proxy health check
+kube_proxy_healthz_bind_address: 0.0.0.0:10256
+
+# If using the pure iptables proxy, SNAT everything. Note that it breaks any
+# policy engine.
+kube_proxy_masquerade_all: false
+
+# If using the pure iptables proxy, the bit of the fwmark space to mark packets requiring SNAT with.
+# Must be within the range [0, 31].
+kube_proxy_masquerade_bit: 14
+
+# The minimum interval of how often the iptables or ipvs rules can be refreshed as
+# endpoints and services change (e.g. '5s', '1m', '2h22m').
+kube_proxy_min_sync_period: 0s
+
+# The maximum interval of how often iptables or ipvs rules are refreshed (e.g. '5s', '1m', '2h22m').
+# Must be greater than 0.
+kube_proxy_sync_period: 30s
+
+# A comma-separated list of CIDR's which the ipvs proxier should not touch when cleaning up IPVS rules.
+kube_proxy_exclude_cidrs: []
+
+# The ipvs scheduler type when proxy mode is ipvs
+# rr: round-robin
+# lc: least connection
+# dh: destination hashing
+# sh: source hashing
+# sed: shortest expected delay
+# nq: never queue
+kube_proxy_scheduler: rr
+
+# configure arp_ignore and arp_announce to avoid answering ARP queries from kube-ipvs0 interface
+# must be set to true for MetalLB to work
+kube_proxy_strict_arp: false
+
+# The IP address and port for the metrics server to serve on
+# (set to 0.0.0.0 for all IPv4 interfaces and `::` for all IPv6 interfaces)
+kube_proxy_metrics_bind_address: 127.0.0.1:10249
+
+# A string slice of values which specify the addresses to use for NodePorts.
+# Values may be valid IP blocks (e.g. 1.2.3.0/24, 1.2.3.4/32).
+# The default empty string slice ([]) means to use all local addresses.
+kube_proxy_nodeport_addresses: >-
+  {%- if kube_proxy_nodeport_addresses_cidr is defined -%}
+  [{{ kube_proxy_nodeport_addresses_cidr }}]
+  {%- else -%}
+  []
+  {%- endif -%}
+
+# oom-score-adj value for kube-proxy process. Values must be within the range [-1000, 1000]
+kube_proxy_oom_score_adj: -999
+
+# portRange is the range of host ports (beginPort-endPort, inclusive) that may be consumed
+# in order to proxy service traffic. If unspecified, 0, or (0-0) then ports will be randomly chosen.
+kube_proxy_port_range: ''
+
+# udpIdleTimeout is how long an idle UDP connection will be kept open (e.g. '250ms', '2s').
+# Must be greater than 0. Only applicable for proxyMode=userspace.
+kube_proxy_udp_idle_timeout: 250ms
+
+# If non-empty, will use this string as identification instead of the actual hostname
+kube_override_hostname: >-
+  {%- if cloud_provider is defined and cloud_provider in [ 'aws' ] -%}
+  {%- else -%}
+  {{ inventory_hostname }}
+  {%- endif -%}

diff --git a/roles/kubernetes/master/tasks/kubeadm-setup.yml b/roles/kubernetes/master/tasks/kubeadm-setup.yml
index 8271546..187cecd 100644
--- a/roles/kubernetes/master/tasks/kubeadm-setup.yml
+++ b/roles/kubernetes/master/tasks/kubeadm-setup.yml
@@ -91,6 +91,11 @@
     kubeadmConfig_api_version: v1alpha2
   when: kubeadm_output.stdout|version_compare('v1.11.0', '>=')
 
+- name: defaults kubeadm api version to v1beta1
+  set_fact:
+    kubeadmConfig_api_version: v1beta1
+  when: kubeadm_output.stdout|version_compare('v1.13.0', '>=')
+
 # Nginx LB(default), If kubeadm_config_api_fqdn is defined, use other LB by kubeadm controlPlaneEndpoint.
 - name: set kubeadm_config_api_fqdn define
   set_fact:
@@ -130,10 +135,11 @@
   notify: Master | restart kubelet
 
 # FIXME(mattymo): remove when https://github.com/kubernetes/kubeadm/issues/433 is fixed
-- name: kubeadm | Enable kube-proxy
-  command: "{{ bin_dir }}/kubeadm alpha phase addon kube-proxy --config={{ kube_config_dir }}/kubeadm-config.{{ kubeadmConfig_api_version }}.yaml"
-  when: inventory_hostname == groups['kube-master']|first
-  changed_when: false
+# dperiquet: that PR is closed
+#- name: kubeadm | Enable kube-proxy
+#  command: "{{ bin_dir }}/kubeadm alpha phase addon kube-proxy --config={{ kube_config_dir }}/kubeadm-config.{{ kubeadmConfig_api_version }}.yaml"
+#  when: inventory_hostname == groups['kube-master']|first
+#  changed_when: false
 
 - name: slurp kubeadm certs
   slurp:

diff --git a/roles/kubernetes/master/tasks/pre-upgrade.yml b/roles/kubernetes/master/tasks/pre-upgrade.yml
index 56e57b0..9a76fe8 100644
--- a/roles/kubernetes/master/tasks/pre-upgrade.yml
+++ b/roles/kubernetes/master/tasks/pre-upgrade.yml
@@ -8,13 +8,14 @@
   register: old_data_exists
   delegate_to: "{{groups['etcd'][0]}}"
   changed_when: false
-  when: kube_apiserver_storage_backend == "etcd3"
+  # variable shows as undefined even though it exists in main/main.yml
+  #when: kube_apiserver_storage_backend == "etcd3"
   failed_when: false
 
-- name: "Pre-upgrade | etcd3 upgrade | use etcd2 unless forced to etcd3"
-  set_fact:
-    kube_apiserver_storage_backend: "etcd2"
-  when: old_data_exists.rc == 0 and not force_etcd3|bool
+#- name: "Pre-upgrade | etcd3 upgrade | use etcd2 unless forced to etcd3"
+#  set_fact:
+#    kube_apiserver_storage_backend: "etcd2"
+#  when: old_data_exists.rc == 0 and not force_etcd3|bool
 
 - name: "Pre-upgrade | Delete master manifests"
   file:
@@ -33,4 +34,4 @@
   register: remove_master_container
   retries: 4
   until: remove_master_container.rc == 0
-  delay: 5
\ No newline at end of file
+  delay: 5

diff --git a/roles/kubernetes/master/templates/kubeadm-config.v1beta1.yaml.j2 b/roles/kubernetes/master/templates/kubeadm-config.v1beta1.yaml.j2
new file mode 100644
index 0000000..4f8e411
--- /dev/null
+++ b/roles/kubernetes/master/templates/kubeadm-config.v1beta1.yaml.j2
@@ -0,0 +1,293 @@
+apiVersion: kubeadm.k8s.io/v1beta1
+kind: InitConfiguration
+localAPIEndpoint:
+  advertiseAddress: {{ ip | default(fallback_ips[inventory_hostname]) }}
+  bindPort: {{ kube_apiserver_port }}
+nodeRegistration:
+{% if kube_override_hostname|default('') %}
+  name: {{ kube_override_hostname }}
+{% endif %}
+{% if inventory_hostname in groups['kube-master'] and inventory_hostname not in groups['kube-node'] %}
+  taints:
+  - effect: NoSchedule
+    key: node-role.kubernetes.io/master
+{% endif %}
+{% if container_manager == 'crio' %}
+  criSocket: /var/run/crio/crio.sock
+{% elif container_manager == 'rkt' %}
+  criSocket: /var/run/rkt.sock
+{% else %}
+  criSocket: /var/run/dockershim.sock
+{% endif %}
+---
+apiVersion: kubeadm.k8s.io/v1beta1
+kind: ClusterConfiguration
+clusterName: {{ cluster_name }}
+etcd:
+  external:
+      endpoints:
+{% for endpoint in etcd_access_addresses.split(',') %}
+      - {{ endpoint }}
+{% endfor %}
+      caFile: {{ etcd_cert_dir }}/ca.pem
+      certFile: {{ etcd_cert_dir }}/node-{{ inventory_hostname }}.pem
+      keyFile: {{ etcd_cert_dir }}/node-{{ inventory_hostname }}-key.pem
+networking:
+  dnsDomain: {{ dns_domain }}
+  serviceSubnet: {{ kube_service_addresses }}
+  podSubnet: {{ kube_pods_subnet }}
+kubernetesVersion: {{ kube_version }}
+{% if kubeadm_config_api_fqdn is defined %}
+controlPlaneEndpoint: {{ kubeadm_config_api_fqdn }}:{{ loadbalancer_apiserver.port | default(kube_apiserver_port) }}
+{% else %}
+controlPlaneEndpoint: {{ ip | default(fallback_ips[inventory_hostname]) }}:{{ kube_apiserver_port }}
+{% endif %}
+certificatesDir: {{ kube_cert_dir }}
+imageRepository: {{ kube_image_repo }}
+useHyperKubeImage: false
+apiServer:
+  extraArgs:
+    authorization-mode: {{ authorization_modes | join(',') }}
+    bind-address: {{ kube_apiserver_bind_address }}
+{% if kube_apiserver_insecure_port|string != "0" %}
+    insecure-bind-address: {{ kube_apiserver_insecure_bind_address }}
+{% endif %}
+    insecure-port: "{{ kube_apiserver_insecure_port }}"
+{% if kube_version | version_compare('v1.10', '<') %}
+    admission-control: {{ kube_apiserver_admission_control | join(',') }}
+{% else %}
+{% if kube_apiserver_enable_admission_plugins|length > 0 %}
+    enable-admission-plugins: {{ kube_apiserver_enable_admission_plugins | join(',') }}
+{% endif %}
+{% if kube_apiserver_disable_admission_plugins|length > 0 %}
+    disable-admission-plugins: {{ kube_apiserver_disable_admission_plugins | join(',') }}
+{% endif %}
+{% endif %}
+    apiserver-count: "{{ kube_apiserver_count }}"
+{% if kube_version | version_compare('v1.9', '>=') %}
+    endpoint-reconciler-type: lease
+{% endif %}
+{% if etcd_events_cluster_enabled %}
+    etcd-servers-overrides: "/events#{{ etcd_events_access_addresses }}"
+{% endif %}
+    service-node-port-range: {{ kube_apiserver_node_port_range }}
+    kubelet-preferred-address-types: "{{ kubelet_preferred_address_types }}"
+{% if kube_basic_auth|default(true) %}
+    basic-auth-file: {{ kube_users_dir }}/known_users.csv
+{% endif %}
+{% if kube_token_auth|default(true) %}
+    token-auth-file: {{ kube_token_dir }}/known_tokens.csv
+{% endif %}
+{% if kube_oidc_auth|default(false) and kube_oidc_url is defined and kube_oidc_client_id is defined %}
+    oidc-issuer-url: {{ kube_oidc_url }}
+    oidc-client-id: {{ kube_oidc_client_id }}
+{%   if kube_oidc_ca_file is defined %}
+    oidc-ca-file: {{ kube_oidc_ca_file }}
+{%   endif %}
+{%   if kube_oidc_username_claim is defined %}
+    oidc-username-claim: {{ kube_oidc_username_claim }}
+{%   endif %}
+{%   if kube_oidc_groups_claim is defined %}
+    oidc-groups-claim: {{ kube_oidc_groups_claim }}
+{%   endif %}
+{%   if kube_oidc_username_prefix is defined %}
+    oidc-username-prefix: {{ kube_oidc_username_prefix }}
+{%   endif %}
+{%   if kube_oidc_groups_prefix is defined %}
+    oidc-groups-prefix: {{ kube_oidc_groups_prefix }}
+{%   endif %}
+{% endif %}
+{% if kube_webhook_token_auth|default(false) %}
+    authentication-token-webhook-config-file: {{ kube_config_dir }}/webhook-token-auth-config.yaml
+{% endif %}
+{% if kube_encrypt_secret_data %}
+    encryption-provider-config: {{ kube_cert_dir }}/secrets_encryption.yaml
+{% endif %}
+    storage-backend: {{ kube_apiserver_storage_backend }}
+{% if kube_api_runtime_config is defined %}
+    runtime-config: {{ kube_api_runtime_config | join(',') }}
+{% endif %}
+    allow-privileged: "true"
+{% if kubernetes_audit %}
+    audit-log-path: "{{ audit_log_path }}"
+    audit-log-maxage: "{{ audit_log_maxage }}"
+    audit-log-maxbackup: "{{ audit_log_maxbackups }}"
+    audit-log-maxsize: "{{ audit_log_maxsize }}"
+    audit-policy-file: {{ audit_policy_file }}
+{% endif %}
+{% for key in kube_kubeadm_apiserver_extra_args %}
+    {{ key }}: "{{ kube_kubeadm_apiserver_extra_args[key] }}"
+{% endfor %}
+{% if kube_feature_gates %}
+    feature-gates: {{ kube_feature_gates|join(',') }}
+{% endif %}
+{% if cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws"] %}
+    cloud-provider: {{cloud_provider}}
+    cloud-config: {{ kube_config_dir }}/cloud_config
+{% elif cloud_provider is defined and cloud_provider in ["external"] %}
+    cloud-config: {{ kube_config_dir }}/cloud_config
+{% endif %}
+{% if kubernetes_audit or kube_basic_auth|default(true) or kube_token_auth|default(true) or kube_webhook_token_auth|default(false) or ( cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws"] ) or apiserver_extra_volumes or ssl_ca_dirs|length %}
+  extraVolumes:
+{% if cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws", "external"] %}
+  - name: cloud-config
+    hostPath: {{ kube_config_dir }}/cloud_config
+    mountPath: {{ kube_config_dir }}/cloud_config
+{% endif %}
+{% if kube_basic_auth|default(true) %}
+  - name: basic-auth-config
+    hostPath: {{ kube_users_dir }}
+    mountPath: {{ kube_users_dir }}
+{% endif %}
+{% if kube_token_auth|default(true) %}
+  - name: token-auth-config
+    hostPath: {{ kube_token_dir }}
+    mountPath: {{ kube_token_dir }}
+{% endif %}
+{% if kube_webhook_token_auth|default(false) %}
+  - name: webhook-token-auth-config
+    hostPath: {{ kube_config_dir }}/webhook-token-auth-config.yaml
+    mountPath: {{ kube_config_dir }}/webhook-token-auth-config.yaml
+{% endif %}
+{% if kubernetes_audit %}
+  - name: {{ audit_policy_name }}
+    hostPath: {{ audit_policy_hostpath }}
+    mountPath: {{ audit_policy_mountpath }}
+{% if audit_log_path != "-" %}
+  - name: {{ audit_log_name }}
+    hostPath: {{ audit_log_hostpath }}
+    mountPath: {{ audit_log_mountpath }}
+    readOnly: false
+{% endif %}
+{% endif %}
+{% for volume in apiserver_extra_volumes %}
+  - name: {{ volume.name }}
+    hostPath: {{ volume.hostPath }}
+    mountPath: {{ volume.mountPath }}
+    readOnly: {{ volume.readOnly | d(not (volume.writable | d(false))) }}
+{% endfor %}
+{% if ssl_ca_dirs|length %}
+{% for dir in ssl_ca_dirs %}
+  - name: {{ dir | regex_replace('^/(.*)$', '\\1' ) | regex_replace('/', '-') }}
+    hostPath: {{ dir }}
+    mountPath: {{ dir }}
+    readOnly: true
+{% endfor %}
+{% endif %}
+{% endif %}
+  certSANs:
+    - kubernetes
+    - kubernetes.default
+    - kubernetes.default.svc
+    - kubernetes.default.svc.{{ dns_domain }}
+    - {{ kube_apiserver_ip }}
+    - localhost
+    - 127.0.0.1
+{% for host in groups['kube-master'] %}
+    - {{ hostvars[host]['ip'] }}
+{% endfor %}
+  timeoutForControlPlane: 5m0s
+controllerManager:
+  extraArgs:
+    node-monitor-grace-period: {{ kube_controller_node_monitor_grace_period }}
+    node-monitor-period: {{ kube_controller_node_monitor_period }}
+    pod-eviction-timeout: {{ kube_controller_pod_eviction_timeout }}
+    node-cidr-mask-size: "{{ kube_network_node_prefix }}"
+{% if kube_version | version_compare('v1.14', '<') %}
+    address: {{ kube_controller_manager_bind_address }}
+{% else %}
+    bind-address: {{ kube_controller_manager_bind_address }}
+{% endif %}
+{% if kube_feature_gates %}
+    feature-gates: {{ kube_feature_gates|join(',') }}
+{% endif %}
+{% for key in kube_kubeadm_controller_extra_args %}
+    {{ key }}: "{{ kube_kubeadm_controller_extra_args[key] }}"
+{% endfor %}
+{% if cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws"] %}
+    cloud-provider: {{cloud_provider}}
+    cloud-config: {{ kube_config_dir }}/cloud_config
+{% elif cloud_provider is defined and cloud_provider in ["external"] %}
+    cloud-config: {{ kube_config_dir }}/cloud_config
+{% endif %}
+{% if cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws", "external"] or controller_manager_extra_volumes %}
+  extraVolumes:
+{% if cloud_provider is defined and cloud_provider in ["openstack"] and openstack_cacert is defined %}
+  - name: openstackcacert
+    hostPath: "{{ kube_config_dir }}/openstack-cacert.pem"
+    mountPath: "{{ kube_config_dir }}/openstack-cacert.pem"
+{% endif %}
+{% if cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws", "external"] %}
+  - name: cloud-config
+    hostPath: {{ kube_config_dir }}/cloud_config
+    mountPath: {{ kube_config_dir }}/cloud_config
+{% endif %}
+{% for volume in controller_manager_extra_volumes %}
+  - name: {{ volume.name }}
+    hostPath: {{ volume.hostPath }}
+    mountPath: {{ volume.mountPath }}
+    readOnly: {{ volume.readOnly | d(not (volume.writable | d(false))) }}
+{% endfor %}
+{% endif %}
+scheduler:
+  extraArgs:
+{% if kube_version | version_compare('v1.14', '<') %}
+    address: {{ kube_scheduler_bind_address }}
+{% else %}
+    bind-address: {{ kube_scheduler_bind_address }}
+{% endif %}
+{% if kube_feature_gates %}
+    feature-gates: {{ kube_feature_gates|join(',') }}
+{% endif %}
+{% if kube_kubeadm_scheduler_extra_args|length > 0 %}
+{% for key in kube_kubeadm_scheduler_extra_args %}
+    {{ key }}: "{{ kube_kubeadm_scheduler_extra_args[key] }}"
+{% endfor %}
+{% endif %}
+  extraVolumes:
+{% if scheduler_extra_volumes %}
+  extraVolumes:
+{% for volume in scheduler_extra_volumes %}
+  - name: {{ volume.name }}
+    hostPath: {{ volume.hostPath }}
+    mountPath: {{ volume.mountPath }}
+    readOnly: {{ volume.readOnly | d(not (volume.writable | d(false))) }}
+{% endfor %}
+{% endif %}
+---
+apiVersion: kubeproxy.config.k8s.io/v1alpha1
+kind: KubeProxyConfiguration
+bindAddress: {{ kube_proxy_bind_address }}
+clientConnection:
+ acceptContentTypes: {{ kube_proxy_client_accept_content_types }}
+ burst: {{ kube_proxy_client_burst }}
+ contentType: {{ kube_proxy_client_content_type }}
+ kubeconfig: {{ kube_proxy_client_kubeconfig }}
+ qps: {{ kube_proxy_client_kubeconfig }}
+clusterCIDR: {{ kube_pods_subnet }}
+configSyncPeriod: {{ kube_proxy_config_sync_period }}
+conntrack:
+ max: {{ kube_proxy_conntrack_max }}
+ maxPerCore: {{ kube_proxy_conntrack_max_per_core }}
+ min: {{ kube_proxy_conntrack_min }}
+ tcpCloseWaitTimeout: {{ kube_proxy_conntrack_tcp_close_wait_timeout }}
+ tcpEstablishedTimeout: {{ kube_proxy_conntrack_tcp_established_timeout }}
+enableProfiling: {{ kube_proxy_enable_profiling }}
+healthzBindAddress: {{ kube_proxy_healthz_bind_address }}
+hostnameOverride: {{ kube_override_hostname }}
+iptables:
+ masqueradeAll: {{ kube_proxy_masquerade_all }}
+ masqueradeBit: {{ kube_proxy_masquerade_bit }}
+ minSyncPeriod: {{ kube_proxy_min_sync_period }}
+ syncPeriod: {{ kube_proxy_sync_period }}
+ipvs:
+ excludeCIDRs: {{ kube_proxy_exclude_cidrs }}
+ minSyncPeriod: {{ kube_proxy_min_sync_period }}
+ scheduler: {{ kube_proxy_scheduler }}
+ syncPeriod: {{ kube_proxy_sync_period }}
+metricsBindAddress: {{ kube_proxy_metrics_bind_address }}
+mode: {{ kube_proxy_mode }}
+nodePortAddresses: {{ kube_proxy_nodeport_addresses }}
+oomScoreAdj: {{ kube_proxy_oom_score_adj }}
+portRange: {{ kube_proxy_port_range }}
+udpIdleTimeout: {{ kube_proxy_udp_idle_timeout }}

diff --git a/roles/kubernetes/node/tasks/install.yml b/roles/kubernetes/node/tasks/install.yml
index ceeaa44..a9f2b40 100644
--- a/roles/kubernetes/node/tasks/install.yml
+++ b/roles/kubernetes/node/tasks/install.yml
@@ -30,6 +30,14 @@
 
 - include_tasks: "install_{{ kubelet_deployment_type }}.yml"
 
+- name: Write the custom /etc/kresolv.conf (kubeadm)
+  template:
+    src: kresolv.conf
+    dest: "/etc/kresolv.conf"
+  when: kubeadm_enabled
+  tags:
+    - kubeadm
+
 - name: install | Write kubelet systemd init file
   template:
     src: "kubelet.{{ kubelet_deployment_type }}.service.j2"

diff --git a/roles/kubernetes/node/templates/kresolv.conf b/roles/kubernetes/node/templates/kresolv.conf
new file mode 100644
index 0000000..5144f9f
--- /dev/null
+++ b/roles/kubernetes/node/templates/kresolv.conf
@@ -0,0 +1,4 @@
+nameserver {{ kube_resolv_ip }}
+nameserver 8.8.8.8
+search default.svc.cluster.local svc.cluster.local cluster.local
+options ndots:5

diff --git a/roles/kubernetes/node/templates/kubelet.kubeadm.env.j2 b/roles/kubernetes/node/templates/kubelet.kubeadm.env.j2
index 8dc19d2..9a784fa 100644
--- a/roles/kubernetes/node/templates/kubelet.kubeadm.env.j2
+++ b/roles/kubernetes/node/templates/kubelet.kubeadm.env.j2
@@ -28,14 +28,19 @@ KUBELET_HOSTNAME="--hostname-override={{ kube_override_hostname }}"
 {% endif %}
 --enforce-node-allocatable={{ kubelet_enforce_node_allocatable }} \
 --client-ca-file={{ kube_cert_dir }}/ca.crt \
+{% if kubelet_rotate_certificates %}
+--rotate-certificates \
+{% endif %}
 --pod-manifest-path={{ kube_manifest_dir }} \
+{% if kube_version | version_compare('v1.12.0', '<') %}
 --cadvisor-port={{ kube_cadvisor_port }} \
+{% endif %}
 {# end kubeadm specific settings #}
 --pod-infra-container-image={{ pod_infra_image_repo }}:{{ pod_infra_image_tag }} \
 --node-status-update-frequency={{ kubelet_status_update_frequency }} \
 --cgroup-driver={{ kubelet_cgroup_driver|default(kubelet_cgroup_driver_detected) }} \
 --max-pods={{ kubelet_max_pods }} \
-{% if container_manager == 'docker' %}
+{% if container_manager == 'docker' and kube_version | version_compare('v1.12.0', '<') %}
 --docker-disable-shared-pid={{ kubelet_disable_shared_pid }} \
 {% endif %}
 {% if container_manager == 'crio' %}
@@ -63,49 +68,67 @@ KUBELET_HOSTNAME="--hostname-override={{ kube_override_hostname }}"
 {% endif %}
 
 {# DNS settings for kubelet #}
-{% if dns_mode in ['kubedns', 'coredns'] %}
+{% if dns_mode == 'coredns' %}
 {% set kubelet_args_cluster_dns %}--cluster-dns={{ skydns_server }}{% endset %}
 {% elif dns_mode == 'coredns_dual' %}
 {% set kubelet_args_cluster_dns %}--cluster-dns={{ skydns_server }},{{ skydns_server_secondary }}{% endset %}
-{% elif dns_mode == 'dnsmasq_kubedns' %}
-{% set kubelet_args_cluster_dns %}--cluster-dns={{ dnsmasq_dns_server }}{% endset %}
 {% elif dns_mode == 'manual' %}
 {% set kubelet_args_cluster_dns %}--cluster-dns={{ manual_dns_server }}{% endset %}
 {% else %}
 {% set kubelet_args_cluster_dns %}{% endset %}
 {% endif %}
+{% if enable_nodelocaldns == True %}
+{% set kubelet_args_cluster_dns %}--cluster-dns={{ nodelocaldns_ip }}{% endset %}
+{% endif %}
 {% set kubelet_args_dns %}{{ kubelet_args_cluster_dns }} --cluster-domain={{ dns_domain }} --resolv-conf={{ kube_resolv_conf }}{% endset %}
 
 {# Kubelet node labels #}
 {% set role_node_labels = [] %}
 {% if inventory_hostname in groups['kube-master'] %}
-{%   set dummy = role_node_labels.append('node-role.kubernetes.io/master=true') %}
+{%   set dummy = role_node_labels.append("node-role.kubernetes.io/master=''") %}
 {%   if not standalone_kubelet|bool %}
-{%     set dummy = role_node_labels.append('node-role.kubernetes.io/node=true') %}
+{%     set dummy = role_node_labels.append("node-role.kubernetes.io/node=''") %}
 {%   endif %}
 {% else %}
-{%   set dummy = role_node_labels.append('node-role.kubernetes.io/node=true') %}
+{%   set dummy = role_node_labels.append("node-role.kubernetes.io/node=''") %}
+{% endif %}
+{% if nvidia_gpu_nodes is defined and nvidia_accelerator_enabled|bool %}
+{%   if inventory_hostname in nvidia_gpu_nodes %}
+{%     set dummy = role_node_labels.append('nvidia.com/gpu=true')  %}
+{%   endif %}
 {% endif %}
+
 {% set inventory_node_labels = [] %}
-{% if node_labels is defined %}
+{% if node_labels is defined and node_labels is mapping %}
 {%   for labelname, labelvalue in node_labels.items() %}
 {%     set dummy = inventory_node_labels.append('%s=%s'|format(labelname, labelvalue)) %}
 {%   endfor %}
 {% endif %}
 {% set all_node_labels = role_node_labels + inventory_node_labels %}
 
-KUBELET_ARGS="{{ kubelet_args_base }} {{ kubelet_args_dns }} {{ kube_reserved }} --node-labels={{ all_node_labels | join(',') }} {% if kubelet_custom_flags is string %} {{kubelet_custom_flags}} {% else %}{% for flag in kubelet_custom_flags %} {{flag}} {% endfor %}{% endif %}{% if inventory_hostname in groups['kube-node'] %}{% if kubelet_node_custom_flags is string %} {{kubelet_node_custom_flags}} {% else %}{% for flag in kubelet_node_custom_flags %} {{flag}} {% endfor %}{% endif %}{% endif %}"
-{% if kube_network_plugin is defined and kube_network_plugin in ["calico", "canal", "flannel", "weave", "contiv", "cilium"] %}
+{# Kubelet node taints for gpu #}
+{% if nvidia_gpu_nodes is defined and nvidia_accelerator_enabled|bool %}
+{%   if inventory_hostname in nvidia_gpu_nodes and node_taints is defined %}
+{%       set dummy = node_taints.append('nvidia.com/gpu=:NoSchedule') %}
+{%   elif inventory_hostname in nvidia_gpu_nodes and node_taints is not defined %}
+{%       set node_taints = [] %}
+{%       set dummy = node_taints.append('nvidia.com/gpu=:NoSchedule') %}
+{%   endif %}
+{% endif %}
+
+KUBELET_ARGS="{{ kubelet_args_base }} {{ kubelet_args_dns }} {{ kube_reserved }} {% if node_taints|default([]) %}--register-with-taints={{ node_taints | join(',') }} {% endif %}--node-labels={{ all_node_labels | join(',') }} {% if kube_feature_gates %} --feature-gates={{ kube_feature_gates|join(',') }} {% endif %} {% if kubelet_custom_flags is string %} {{kubelet_custom_flags}} {% else %}{% for flag in kubelet_custom_flags %} {{flag}} {% endfor %}{% endif %}{% if inventory_hostname in groups['kube-node'] %}{% if kubelet_node_custom_flags is string %} {{kubelet_node_custom_flags}} {% else %}{% for flag in kubelet_node_custom_flags %} {{flag}} {% endfor %}{% endif %}{% endif %}"
+{% if kube_network_plugin is defined and kube_network_plugin in ["calico", "canal", "flannel", "weave", "contiv", "cilium", "kube-router"] %}
 KUBELET_NETWORK_PLUGIN="--network-plugin=cni --cni-conf-dir=/etc/cni/net.d --cni-bin-dir=/opt/cni/bin"
 {% elif kube_network_plugin is defined and kube_network_plugin == "cloud" %}
 KUBELET_NETWORK_PLUGIN="--hairpin-mode=promiscuous-bridge --network-plugin=kubenet"
 {% endif %}
+KUBELET_VOLUME_PLUGIN="--volume-plugin-dir={{ kubelet_flexvolumes_plugins_dir }}"
 # Should this cluster be allowed to run privileged docker containers
 KUBE_ALLOW_PRIV="--allow-privileged=true"
 {% if cloud_provider is defined and cloud_provider in ["openstack", "azure", "vsphere", "aws"] %}
 KUBELET_CLOUDPROVIDER="--cloud-provider={{ cloud_provider }} --cloud-config={{ kube_config_dir }}/cloud_config"
-{% elif cloud_provider is defined and cloud_provider in ["oci", "external"] %}
-KUBELET_CLOUDPROVIDER="--cloud-provider=external"
+{% elif cloud_provider is defined and cloud_provider in ["external"] %}
+KUBELET_CLOUDPROVIDER="--cloud-provider=external --cloud-config={{ kube_config_dir }}/cloud_config"
 {% else %}
 KUBELET_CLOUDPROVIDER=""
 {% endif %}

diff --git a/roles/kubespray-defaults/defaults/main.yaml b/roles/kubespray-defaults/defaults/main.yaml
index 359bad3..b030f84 100644
--- a/roles/kubespray-defaults/defaults/main.yaml
+++ b/roles/kubespray-defaults/defaults/main.yaml
@@ -47,6 +47,11 @@ ndots: 2
 # Can be dnsmasq_kubedns, kubedns, manual or none
 dns_mode: kubedns
 
+# Enable nodelocal dns cache
+enable_nodelocaldns: false
+nodelocaldns_ip: 169.254.25.10
+nodelocaldns_health_port: 9254
+
 # Should be set to a cluster IP if using a custom cluster DNS
 # manual_dns_server: 10.x.x.x
 
@@ -276,6 +281,10 @@ kubelet_authentication_token_webhook: true
 # When enabled, access to the kubelet API requires authorization by delegation to the API server
 kubelet_authorization_mode_webhook: false
 
+# kubelet uses certificates for authenticating to the Kubernetes API
+# Automatically generate a new key and request a new certificate from the Kubernetes API as the current certificate approaches expiration
+kubelet_rotate_certificates: true
+
 ## List of key=value pairs that describe feature gates for
 ## the k8s cluster.
 kube_feature_gates:
@@ -314,6 +323,14 @@ contiv_peer_with_uplink_leaf: false
 contiv_global_as: "65002"
 contiv_global_neighbor_as: "500"
 
+# Set 127.0.0.1 as fallback IP if we do not have host facts for host
+fallback_ips_base: |
+  ---
+  {% for item in groups['k8s-cluster'] + groups['etcd'] + groups['calico-rr']|default([])|unique %}
+  {{ item }}: "{{ hostvars[item].get('ansible_default_ipv4', {'address': '127.0.0.1'})['address'] }}"
+  {% endfor %}
+fallback_ips: "{{ fallback_ips_base | from_yaml }}"
+
 ## Set no_proxy to all assigned cluster IPs and hostnames
 no_proxy: >-
   {%- if http_proxy is defined or https_proxy is defined %}
```

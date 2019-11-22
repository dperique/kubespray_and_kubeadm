# Summary

* I put all the changes I made in the `xxxx:Dennis-Periquet/kubespray.git`
  using branch=kubeadm_1.13.10
* I used kubeadm-test k8s cluster; see `.../group_vars/all`

```
...
kubespray_tag: v2.7.0
docker_version: '18.09'
kube_version: v1.13.10
kubeadm_enabled: true                         <-- see this
kube_resolv_conf: '/etc/kresolv.conf'         <-- see this
kube_resolv_ip: '10.233.0.3'                  <-- see this

hyperkube_image_repo: "gcr.io/google-containers/hyperkube"
hyperkube_image_tag: "{{ kube_version }}"
```

* I also used etcd-test cluster which resides on kube-stack

```
kubespray_tag: v2.7.0
docker_version: '18.09'
kube_version: v1.13.10
kubeadm_enabled: true                 <-- see this
kube_resolv_conf: '/etc/kresolv.conf' <-- see this
kube_resolv_ip: '10.239.0.3'          <-- see this

# For Kubernetes 1.14+, use admissionsregistration.k8s.io
# For Kubernetes 1.16+, use extensions/v1beta1/daemonsets for fluentd until Kubernetes 1.18
# For Kubernetes 1.16+, use extensions/v1beta1/deployments for certain until Kubernetes 1.18
# For Kubernetes 1.16+, use apps/v1beta1 for certain deployments until Kubernetes 1.18
# For Kubernetes 1.16+, use apps/v1beta2 for calico deployments until Kubernetes 1.18
#kube_api_runtime_config:
# - admissionregistration.k8s.io/v1beta1
# - extensions/v1beta1/daemonsets=true
# - extensions/v1beta1/deployments=true
# - apps/v1beta1=true
# - apps/v1beta2=true
etcd_version: v3.3.10

hyperkube_image_repo: "gcr.io/google-containers/hyperkube"
hyperkube_image_tag: "{{ kube_version }}"

# Avoid address collisions (only for kube-in-kube)
kube_service_addresses: 10.239.0.0/18
kube_pods_subnet: 10.239.64.0/18
dnsmasq_dns_server: 10.239.0.2
skydns_server: 10.239.0.3

calico_mtu: 1400
```

* See the branch area:

```
lola@dennis-etcd:/tmp/git_repos/kubespray$ pwd
/tmp/git_repos/kubespray
lola@dennis-etcd:/tmp/git_repos/kubespray$ git status
On branch kubeadm_1.13.10
Your branch is up-to-date with 'origin/kubeadm_1.13.10'.
nothing to commit, working directory clean
```

* There was a problem with DNS in kube-in-kube (using the etcd-test cluster
  which is inside kube-stack) so we customized the `/etc/resolv.conf` file to
  workaround it.  Due to this, we still cannot rollout kubeadm method of
  creating/maintaning Kubernetes.

* The conclusion was that I was able to install Kubernetes from scratch
  using kubeadm but had to make a lot of modifications to kubespray v2.7.0
  to get it to work.  These two things complicated the work:

  * Kubernetes v1.13.x was is not supported for kubeadm in kubespray v2.7.0
  * I believe kubespray v2.9.0 is supported and had to try to backport many
    changes.

  I have not even begun the work on how to convert an existing Kubernetes
  cluster to move to kubeadm.  This is supposed to be supported by kubespray
  v2.7.0 but it most likely will need debugging.

# More notes from my investigation

You need to:

* get the v1alpha3 templates from upstream or run the kubeadm_1.12 migrate
* convert unifiedControlPlaneImage="gcr.io/google-containers/hyperkube:v1.13.10" to "useHyperKubeImage: true"
* Remove these two flags from the /etc/kubernetes/kubelet.env
  * --cadvisor-port
  * --docker-disable-shared-pid

NOTE: "SAC" refers to Scheduler, Apiserver, Controller

Debugging:

* when kubeadm is not working or is hung, look at:
  * kubelet ; see `systemctl status kubelet`, `journalctl -fu kubelet` (look for obsolete flags)
  * `docker ps|grep api` or the rest of SAC ; `cat /var/log/containers/kube-api*` or other logs
  * Remove wrong flags in /etc/kubernetes/kubelet.env, manifests/kube-api, kube-scheduler, kube-controller

Taking code from kubespray v2.9.0:

  * Take kubernetes/master/templates/kubeadm-config.v1beta1.yaml.j2 required for Kubernetes v1.13+
  * Look at kubernetes/master/tasks/kubeadm-version.yml
    * Get `sets kubeadm api version to v1beta1` to support Kubernetes v1.13+
    * This avoids the need to do a kubeadm migrate
  * Take roles/kubernetes/node/templates/kubelet.kubeadm.env.j2
    * fix the "version" syntax due to new version of ansible
  * Add these to kubespray-defaults/defaults/main.yaml
    * `kubelet_rotate_certificates: true` consider making it false if it's problematic
    * `enable_nodelocaldns: false` ; make it false to avoid new behavior change
    * `fallback_ips`

This whole file was added in v2.9.0 (so I added it):
  roles/kubernetes/master/defaults/main/kube-proxy.yml see https://github.com/kubernetes-sigs/kubespray/pull/3958
  is defaults/main/main.yaml an ansible 2.8 thing? symptom = variables not being read
    include it into defaults/main.yaml

vi kubernetes/master/tasks/kubeadm-setup.yml
  fixing apiserver_sans
notable PR: https://github.com/kubernetes-sigs/kubespray/pull/4994

Certificates on master 1:

See /etc/kubernetes/kubelet.env
/var/lib/kubelet/pki:

```
root@etcd-test-k8s-node-1:/etc/kubernetes/ssl/etcd# ls -l
total 128
-rwx------ 1 root root 1679 Oct 18 01:12 ca-key.pem
-rwx------ 1 root root 1090 Oct 18 01:12 ca.pem

-rwx------ 1 root root 1679 Oct 18 01:12 admin-etcd-test-k8s-node-1-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 admin-etcd-test-k8s-node-1.pem
-rwx------ 1 root root 1675 Oct 18 01:12 admin-etcd-test-k8s-node-2-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 admin-etcd-test-k8s-node-2.pem
-rwx------ 1 root root 1675 Oct 18 01:12 admin-etcd-test-k8s-node-3-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 admin-etcd-test-k8s-node-3.pem
-rwx------ 1 root root 1675 Oct 18 01:12 admin-etcd-test-k8s-node-4-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 admin-etcd-test-k8s-node-4.pem
-rwx------ 1 root root 1675 Oct 18 01:12 admin-etcd-test-k8s-node-5-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 admin-etcd-test-k8s-node-5.pem

-rwx------ 1 root root 1675 Oct 18 01:12 member-etcd-test-k8s-node-1-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 member-etcd-test-k8s-node-1.pem
-rwx------ 1 root root 1679 Oct 18 01:12 member-etcd-test-k8s-node-2-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 member-etcd-test-k8s-node-2.pem
-rwx------ 1 root root 1679 Oct 18 01:12 member-etcd-test-k8s-node-3-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 member-etcd-test-k8s-node-3.pem
-rwx------ 1 root root 1679 Oct 18 01:12 member-etcd-test-k8s-node-4-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 member-etcd-test-k8s-node-4.pem
-rwx------ 1 root root 1675 Oct 18 01:12 member-etcd-test-k8s-node-5-key.pem
-rwx------ 1 root root 1558 Oct 18 01:12 member-etcd-test-k8s-node-5.pem

-rwx------ 1 root root 1675 Oct 18 01:12 node-etcd-test-k8s-node-1-key.pem
-rwx------ 1 root root 1554 Oct 18 01:12 node-etcd-test-k8s-node-1.pem
-rwx------ 1 root root 1675 Oct 18 01:12 node-etcd-test-k8s-node-2-key.pem
-rwx------ 1 root root 1554 Oct 18 01:12 node-etcd-test-k8s-node-2.pem
-rwx------ 1 root root 1675 Oct 18 01:12 node-etcd-test-k8s-node-3-key.pem
-rwx------ 1 root root 1554 Oct 18 01:12 node-etcd-test-k8s-node-3.pem
-rwx------ 1 root root 1679 Oct 18 01:12 node-etcd-test-k8s-node-4-key.pem
-rwx------ 1 root root 1554 Oct 18 01:12 node-etcd-test-k8s-node-4.pem
-rwx------ 1 root root 1675 Oct 18 01:12 node-etcd-test-k8s-node-5-key.pem
-rwx------ 1 root root 1554 Oct 18 01:12 node-etcd-test-k8s-node-5.pem

root@etcd-test-k8s-node-1:/etc/kubernetes/ssl# ls -l
total 52
-rw-r--r-- 1 root root 1099 Oct 18 01:12 apiserver-kubelet-client.crt
-rw------- 1 root root 1679 Oct 18 01:12 apiserver-kubelet-client.key

-rw-r--r-- 1 root root 1440 Oct 18 01:12 apiserver.crt
-rw------- 1 root root 1679 Oct 18 01:12 apiserver.key

-rw-r--r-- 1 root root 1025 Oct 18 01:12 ca.crt
-rw------- 1 root root 1679 Oct 18 01:12 ca.key

drwx------ 2 root root 4096 Oct 18 01:12 etcd

-rw-r--r-- 1 root root 1038 Oct 18 01:12 front-proxy-ca.crt
-rw------- 1 root root 1675 Oct 18 01:12 front-proxy-ca.key

-rw-r--r-- 1 root root 1058 Oct 18 01:12 front-proxy-client.crt
-rw------- 1 root root 1675 Oct 18 01:12 front-proxy-client.key

-rw------- 1 root root 1679 Oct 18 01:12 sa.key
-rw------- 1 root root  451 Oct 18 01:12 sa.pub
```

Install v1.13.10 kubeadm and get this:

```
fatal: [etcd-test-k8s-node-1]: FAILED! => {"changed": true, "cmd": ["timeout", "-k", "600s", "600s", "/usr/local/bin/kubeadm", "upgrade", "apply", "-y", "v1.13.10", "--config=/etc/kubernetes/kubeadm-config.v1alpha2.yaml", "--ignore-preflight-errors=all", "--allow-experimental-upgrades", "--allow-release-candidate-upgrades", "--force"], "delta": "0:00:00.043915", "end": "2019-10-15 01:49:48.413841", "failed": true, "failed_when_result": true, "msg": "non-zero return code", "rc": 1, "start": "2019-10-15 01:49:48.369926", "stderr": "your configuration file uses an old API spec: \"kubeadm.k8s.io/v1alpha2\". Please use kubeadm v1.12 instead and run 'kubeadm config migrate --old-config old.yaml --new-config new.yaml', which will write the new, similar spec using a newer API version.", "stderr_lines": ["your configuration file uses an old API spec: \"kubeadm.k8s.io/v1alpha2\". Please use kubeadm v1.12 instead and run 'kubeadm config migrate --old-config old.yaml --new-config new.yaml', which will write the new, similar spec using a newer API version."], "stdout": "[preflight] Running pre-flight checks.", "stdout_lines": ["[preflight] Running pre-flight checks."]}
```

Try:

```
root@etcd-test-k8s-node-1:~# ./kubeadm config migrate --old-config old.yaml --new-config new.yaml

root@etcd-test-k8s-node-1:~# less new.yaml
root@etcd-test-k8s-node-1:~# /usr/local/bin/kubeadm upgrade apply -y v1.13.10 --config=/etc/kubernetes/kubeadm-config.v1alpha2.yaml --ignore-preflight-errors=all --allow-experimental-upgrades --allow-release-candidate-upgrades --force"

root@etcd-test-k8s-node-1:~# ^C
root@etcd-test-k8s-node-1:~# cp new.yaml /etc/kubernetes/kubeadm-config.v1alpha2.yaml
root@etcd-test-k8s-node-1:~# /usr/local/bin/kubeadm upgrade apply -y v1.13.10 --config=/etc/kubernetes/kubeadm-config.v1alpha2.yaml --ignore-preflight-errors=all --allow-experimental-upgrades --allow-release-candidate-upgrades --force"
> ^C
root@etcd-test-k8s-node-1:~# /usr/local/bin/kubeadm upgrade apply -y v1.13.10 --config=/etc/kubernetes/kubeadm-config.v1alpha2.yaml --ignore-preflight-errors=all --allow-experimental-upgrades --allow-release-candidate-upgrades --force
[preflight] Running pre-flight checks.
cannot convert unifiedControlPlaneImage="gcr.io/google-containers/hyperkube:v1.13.10" to useHyperKubeImage
root@etcd-test-k8s-node-1:~# exit

root@etcd-test-k8s-node-1:~# ./kubeadm config migrate --old-config /etc/kubernetes/kubeadm-config.v1alpha2.yaml --new-config n.yaml
root@etcd-test-k8s-node-1:~# cp n.yaml /etc/kubernetes/kubeadm-config.v1alpha2.yaml
root@etcd-test-k8s-node-1:~# /usr/local/bin/kubeadm init --config=/etc/kubernetes/kubeadm-config.v1alpha2.yaml --ignore-preflight-errors=all
cannot convert unifiedControlPlaneImage="gcr.io/google-containers/hyperkube:v1.13.10" to useHyperKubeImage

edit /etc/kubernetes/kubeadm-config.v1alpha2.yaml
  change unifiedControlPlaneImage to "useHyperKubeImage: true"


W1015 02:10:35.054346    3278 strict.go:54] error unmarshaling configuration schema.GroupVersionKind{Group:"kubeadm.k8s.io", Version:"v1alpha3", Kind:"ClusterConfiguration"}: error unmarshaling JSON: while decoding JSON: json: unknown field "useHyperKubeImage"
[init] Using Kubernetes version: v1.13.10
[preflight] Running pre-flight checks
	[WARNING SystemVerification]: this Docker version is not on the list of validated versions: 18.09.7. Latest validated version: 18.06
[preflight] Pulling images required for setting up a Kubernetes cluster
[preflight] This might take a minute or two, depending on the speed of your internet connection
[preflight] You can also perform this action in beforehand using 'kubeadm config images pull'
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Activating the kubelet service
[certs] Using certificateDir folder "/etc/kubernetes/ssl"
[certs] External etcd mode: Skipping etcd/ca certificate authority generation
[certs] External etcd mode: Skipping etcd/peer certificate authority generation
[certs] External etcd mode: Skipping apiserver-etcd-client certificate authority generation
[certs] External etcd mode: Skipping etcd/server certificate authority generation
[certs] External etcd mode: Skipping etcd/healthcheck-client certificate authority generation
[certs] Generating "front-proxy-ca" certificate and key
[certs] Generating "front-proxy-client" certificate and key
[certs] Generating "ca" certificate and key
[certs] Generating "apiserver-kubelet-client" certificate and key
[certs] Generating "apiserver" certificate and key
[certs] apiserver serving cert is signed for DNS names [etcd-test-k8s-node-1 kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local localhost etcd-test-k8s-node-1 etcd-test-k8s-node-2 etcd-test-k8s-node-3] and IPs [10.239.0.1 10.233.82.159 10.239.0.1 127.0.0.1 10.233.82.159 10.233.71.228 10.233.71.229]
[certs] Generating "sa" key and public key
[kubeconfig] Using kubeconfig folder "/etc/kubernetes"
[kubeconfig] Writing "admin.conf" kubeconfig file
[kubeconfig] Writing "kubelet.conf" kubeconfig file
[kubeconfig] Writing "controller-manager.conf" kubeconfig file
[kubeconfig] Writing "scheduler.conf" kubeconfig file
[control-plane] Using manifest folder "/etc/kubernetes/manifests"
[control-plane] Creating static Pod manifest for "kube-apiserver"
[control-plane] Creating static Pod manifest for "kube-controller-manager"
[control-plane] Creating static Pod manifest for "kube-scheduler"
[wait-control-plane] Waiting for the kubelet to boot up the control plane as static Pods from directory "/etc/kubernetes/manifests". This can take up to 4m0s
[kubelet-check] Initial timeout of 40s passed.
[kubelet-check] It seems like the kubelet isn't running or healthy.
[kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10248/healthz' failed with error: Get http://localhost:10248/healthz: dial tcp 127.0.0.1:10248: connect: connection refused.
[kubelet-check] It seems like the kubelet isn't running or healthy.
[kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10248/healthz' failed with error: Get http://localhost:10248/healthz: dial tcp 127.0.0.1:10248: connect: connection refused.
[kubelet-check] It seems like the kubelet isn't running or healthy.
[kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10248/healthz' failed with error: Get http://localhost:10248/healthz: dial tcp 127.0.0.1:10248: connect: connection refused.
[kubelet-check] It seems like the kubelet isn't running or healthy.
[kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10248/healthz' failed with error: Get http://localhost:10248/healthz: dial tcp 127.0.0.1:10248: connect: connection refused.
```

More errors:

```
Unfortunately, an error has occurred:
	timed out waiting for the condition
```

This error is likely caused by:
	- The kubelet is not running
	- The kubelet is unhealthy due to a misconfiguration of the node in some way (required cgroups disabled)

If you are on a systemd-powered system, you can try to troubleshoot the error with the following commands:
	- 'systemctl status kubelet'
	- 'journalctl -xeu kubelet'

```
Additionally, a control plane component may have crashed or exited when started by the container runtime.
To troubleshoot, list all containers using your preferred container runtimes CLI, e.g. docker.
Here is one example how you may list all Kubernetes containers running in docker:
	- 'docker ps -a | grep kube | grep -v pause'
	Once you have found the failing container, you can inspect its logs with:
	- 'docker logs CONTAINERID'
error execution phase wait-control-plane: couldn't initialize a Kubernetes cluster
```

did `journalctl -fu kubelet`

```
found unknown flag: --cadvisor-port
unknown flag: --docker-disable-shared-pid

vi /etc/kubernetes/kubelet.env ; remove --cadvisor-port flag
```

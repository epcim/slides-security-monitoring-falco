---
layout: cover
theme: seriph # https://sli.dev/themes/gallery.html
background: https://source.unsplash.com/collection/94734566/1920x1080
class: 'text-center'
highlighter: shiki # https://sli.dev/custom/highlighters.html
lineNumbers: false
info: |
  ## Falco
  cloud native security a observability monitoring

  Learn more at [falco.org](https://falco.org)
drawings:
  enabled: true
  persist: false

# Docs
# - https://sli.dev/guide/syntax.html
# - https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet
# - https://www.w3.org/wiki/CSS/Properties/color/keywords
---

# Falco

Cloud native security a observability monitoring

<div class="pt-12">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Dive in! <carbon:arrow-right class="inline"/>
  </span>
</div>

<!-- FIXME, add Vue Clock/watch -->

<div class="abs-br m-6 flex gap-2">
  <a href="https://github.com/epcim/slides-security-monitoring-falco" target="_blank" alt="GitHub"
    class="text-xl icon-btn opacity-50 !border-none !hover:text-white">
    <carbon-logo-github />
  </a>
</div>

<!-- 
Security monitoring byl donedávna obvykle jen o sběru všech možných logů a událostí z infrastruktury a jejich zpětné, často nepoužitelné, analýze. Implementace eBPF v linuxovém jádře ovšem otevřela platformu pro zcela jiný přístup. Observability a tracing v reálném čase při rozumných nárocích na zdroje a minimální footprint v systému. Současně se v cloud a kontejnerovém světě podstatně zvyšují nároky na zabezpečení a audit systémů. 

Přednáška je postavena na zkušenostech z implementace Falco, hardening a testování security compliance cloud systémů. Dozvíte se něco málo o základních technologiích a prostředcích security monitoringu, auditu serverů, kontejnerů a kubernetes s Falco. Konfigurace, deployment, Falco rules a vytváření vlastních pravidel. Integrace s Prometheus alertmanager. Testování a compliance fyzických i cloud serverů. Nakonec se podíváme na analytické možnosti SysFlow.io a alerting.

-->


---
layout: two-cols
---
# Petr Michalec
Speaker

Pracuje jako SRE v F5 Czech Republic s.r.o. 
- 147+ services, ~30 regional datacenters
- (Volterra.io, Mirantis, IBM, ...)


<div style="color: #00b4c8">

n(vi)m lover <mdi-circle-small/> maker <mdi-circle-small/> golfer <mdi-circle-small/> quad fpv pilot


* [twitter.com/epcim](https://twitter.com/epcim)
* [github.com/epcim](https://github.com/epcim), [Gists](https://gist.github.com/epcim)

</div>


::right::
<img src="/images/pmi.jpg" class="m-15 h-80 rounded shadow center" />

<!--
- nedelam security
- devops < config mgmt
- os image build, deployment
-->

---
layout: image-right
image: /funny/camera-agent.png
---

# Security monitoring

SecOps coverage

* detect intrusion
* prevent intrusion
* configuraion encorcement
* audit all critical events
* compliance checks & reporting
* ...

<!--
Home security analogy:
Prevent intrusion               > passwords/two factor, image scanning, fw
- door lock, authz
- wiwndow sensors
- exterior camera
Detect Intrusion                > falco
- motion sensors
- interior cameras
-->

---
layout: center
---
# Security monitoring

Purpose & requirements

<div grid="~ cols-2 gap-4">
<div>

- ...
- Compliance with security standards:
  * PCI DSS, CIS, GDPR
  * HIPPA, NIST, FIPS, FedRAMP

</div>
<div>

- evidence collection
- data availability and traceablity
- measurement and support resources
- tools, policies, processes, reporting

</div>
</div>


<!--
Účel a požadavky

- PCI DSS - Payment Card Industry Data Security Standard
- FIPS - Mandatory standard for the protection of sensitive or valuable data within Federal systems
- CIS - Critical Security Controls (CIS Controls)
- NIST  - National Institute of Standards and Technology
- HIPPA - US, personal informations

--

- CIS Controls are a recommended set of actions for cyber defense that provide specific and actionable ways to thwart the most pervasive attacks.

- PCI DSS is set of requirements intended to ensure that all companies that process, store, or transmit credit card information maintain a secure environment. It was launched on September 7, 2006.

- To become FIPS compliant, a U.S. government agency or contractor’s computer systems must meet requirements outlined in the FIPS publications numbered 140, 180, 186, 197, 198, 199, 200, 201, and 202. Introduced 2014.

- FIPS 140 covers cryptographic module and testing requirements in both hardware and software.
 -->


---

# Traditional approach ~2015

Topics and tools

<div grid="~ cols-2 gap-4">
<div>

  - network IDS, WAF
  - filesystem integrity
  - system/service/user audit/logs
  - data access & encryption
  - security threats mittigation
    * CVEs, vulerabilitties
  - mallicious activity detection

</div>
<div>

  - auditd, aide
  - PAM, SElinux, AppArmour
  - OSSEC, OpenSCAP, Inspec, ...
  - Enterprise SIEM tools
  
  <br/>

  SaaS approaching (Snyk, Whitesource, Graylog, Thread stack, ...)

</div>
</div>

<!--
you probably have even today

prikladem: antivirovs detekce, ruzna firewall reseni, WAF

signature based

prohrabavat stara data

how you collect metrics, alerts from  all of these?

--

nainstalujes, par alertu, udelat auditora happy a sjizdis ELK
-->

---
layout: two-cols
---

# New challenges

Microservices

**Containers**
  - namespace isolation
    - container images
      - 3rd party libraries

**Distributed applications**
  - cloud environments ^n
  - 3rd party base images for OS
  - 3rd party accessing servers

**Distributed data**

::right::

<img src="/funny/cloud-monitoring.png" class="m-20 h-80 rounded shadow center" />

<!-- 

* Containers are isolated processes
* Container images are immuteable, runtime environmnts - often aren't

--

- How do you detect "abnormal" behaviour?
- vulnerabilies in ...

distributed, logy uz nejsou na 2-3 msitech
(v databazi ale v zalohach na S3 v cloud atp..)
-->


---
layout: fact
---

# Falco
May 16, 2016 - Sysdig introducing open source, behavioral security

<img src="/images/falco-overview2.png" class="pl-40 h-50 center" />

[Falco.org](https://falco.org) runtime security project detecting unexpected behavior, intrusions, and data theft in real time!

<!-- 
Donated to CNCF
de-facto "Kubernetes, container, cloud" thread detection engine

BEHAVIORAL, premisa

Je nekonecne zpusobu jak se utocnik muze dostat do systemu...

Vy potrebujete detekovat veci, ktere utocnik udela az se tam dostane.
-->

--- 
layout: two-cols
---

# Overview
Falco

- Kernel integration

- Highly granular rules to check for activities involving 
  - file and network activity 
  - process execution 
  - IPC, ...

- Real-time metrics & notification when these rules are violated

- Less complex & faster



::right::

<div class="m-10 pt-15 center" style="color: blueviolet">

*There are a million ways a burglar can break into your home, but once they do they’re going to steal your jewelry.*

<div style="color: #00b4c8">
<br/>
...

*You only need to detect the things that an attacker does once they have access to a system, rather than all the ways an attacker can gain access to a system.*

</div>
</div>

<!-- 

Falco ~~ a mix between snort, ossec and strace
-->

---

# Comparison to existing approaches
Falco

**File integrity monitoring**: (checksums)

<div class="ml-10 center" style="color: #00b4c8">
Watch for any OS activity that is writing to a file of interest, and be alerted in real-time.
</div>
 
**Network monitoring** (signatures)

<div class="ml-10 center" style="color: #00b4c8">
Falco see I/O “from the inside” with an immediate correlation between applications and traffic.
</div>
 
Linux has multiple security modules ~ advanced access control systems with sophisticated policies and concepts. As a result, understanding and configuring them is a rather complex undertaking.

<div class="ml-10 center" style="color: #00b4c8">
Falco is far simpler to understand and configure, "detection-only".
</div>

<!--
Filesystem:

  One way to do file integrity monitoring is to periodically scan all files of interest, compute their checksums, and compare with the checksums of the previous phase.

  The challenge with this kind of approach is that it is costly to scan all files, so one typically runs it every few hours

Networking:

  IDS is inextricably tied to signatures.  With VMs and containers it has become increasingly hard to reconcile network traffic with application activity.

  You can only observe a small slice of system behavior from network traffic.

We can trace activities across all system resources - nic/application/shell/users ...

Linux has multiple security modules, notably including SELinux and AppArmor. These are extremely advanced access control systems with sophisticated policies and concepts. As a result, understanding and configuring them is a rather complex undertaking.
-->

---
layout: center
---

# How it works

Falco architecture

<div class="center">

<img src="/images/falco_architecture.png" class="m-0 h-100 center" />

</div>

<!--

- libscap - capture contorl, dump
- libsinp - event parsing, state engine, filter
- rule engine - rules, in/out


-->

---
layout: center
---

# Kernel integration
Falco

- eBPF
- Built-in
- Module `falco.ko` (w/ DKMS)
- Userspace instrumentation (based on PTRACE2)

<!--
Loader container:
- from pre-build sources for common kernels
- DKMS
- private location
-->

---

# eBPF

- Legacy "Berkeley Packet Filter" (BPF) - technology that among other things allows programs to analyze network traffic (and eBPF is an extended BPF JIT virtual machine in the Linux kernel).

  - raw interface to data link layers
  - permitting raw link-layer packets to be sent and received
  - can run sandboxed programs in a privileged context

<br/>
<div class="center" style="color: blueviolet">

*BPF is a highly flexible and efficient virtual machine-like construct in the Linux kernel allowing to execute bytecode at various hook points in a safe manner. It is used in number of Linux kernel subsystems (networking, tracing, security (snadboxing))"*

</div>


<!-- 

cBPF - Classic BPF, also known as "Linux Packet Filtering", introduced in 1992

eBPF - extended BPF
-->

---
layout: two-cols
---

# SysCalls
eBPF


<img src="/screenshots/ebpf-01.png" class="m-0 h-85 center" />

::right::

<img src="/screenshots/ebpf-07.png" class="m-0 pt-30 h-100 center" />

---
layout: image-right
image: /images/falco-fields-2.png
---

# Why?
eBPF

Enhanced Telemetry Collection -> annotation
- kernel and syscall attributes
- socket info

Performance
- avoid transfer of all audit data to userspace
- lower resource impact (net, file, proc)
- real time procesing

eBPF Verifier verifies the safety of eBPF programs




<!-- 
<img src="/images/ebpf-01.png" class="m-0 h-85 center" />
complex development

BPF kprobes are not stable interface

new sys-calls
-->

---

# Deployment

Falco components

![](/images/falco-components.svg)

---
layout: two-cols
---

# Deployment

K8s & Configuration

Deployment
- Falco-sidekick, prom. exporter
- Falco-sidekick UI
- Grafana dashboards
- Alertmanager, Loki, ES, Kibana
- ..., Plugins

Daemonset
- Falco \
  *(only `falco-driver-loader` needs to be run with `securityContext: priviledged`)*

::right::

<div class="pt-18">

What to enable?
- driver-loader (DKMS, private builds)
- docker, containerd, cri-o
- w/k8s metadata
- custom rules
- threadiness, maxBurst, eventDrops
- priority/severity level
- plugins
  - k8s audit, ...

</div>

<!--
Falco-sidekick (integration with legacy monitoring stack)
Falco-exporter (sidekick does either)
-->
---
layout: two-cols
---

# Language
Syntax, [github.com/falcosecurity/charts/falco/rules](https://github.com/falcosecurity/charts/tree/master/falco/rules)

Macros
- name      (identificator)
- condition (filter)

Lists
- name      (identificator)
- items:    

::right::

<div class="pt-20">

Rules
- `name`      (identificator)
- desc
- `condition` (filter expression, macro)
- `output`    (formated message with **core details**)
- priority  (severity of rule)
- tag
- append
- exceptions (new, not used in upsteream)

</div>

<style>
code {
  color: blueviolet;
};
blockquote {
  code {
    @apply text-teal-500 dark:text-teal-400;
  }
}
</style>

---
layout: default
---

# Primitives
Rules

Shell executed in container

```lua
container.id != host and proc.name = bash
```

Overwirite system bins
```lua
fd.directory in (/bin, /bin/sbin, /usr/bin, /usr/sbin)
and write
```

Container namespace change
```lua
evt.type = setns and not proc.name in (docker)
```

Process access camera
```lua
ect.type = open and fd.name = /dev/video0 and not proc.name in (skype, zoom, webex)
```
---

# Macros & Lists
Rules

```lua
- list: _container_engine_binaries
  items: [dockerd, containerd, containerd-shim, "runc:[0:PARENT]","runc:[1:CHILD]", "runc:[2:INIT]"]

- macro: docker_authorized_binaries
  condition: >
    proc.name in (_container_engine_binaries)
    or proc.pname in (_container_engine_binaries)
```

```lua
" [CVE-2019-11246 on Mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11246)
- macro: safe_kubectl_version
  condition: (
              jevt.value[/useragent] startswith "kubectl/v1.20" or
              jevt.value[/useragent] startswith "kubectl/v1.19"
              ...
            )
```
---


# Filesystem integrity
Rules

```lua {1|3|5|all}
- rule: Detect Write Below /etc/hosts
  desc: an attempt to write to /etc/hosts file (CVE-2020-8557)
  condition: open_write and container and fd.name=/etc/hosts
  output: "File /etc/hosts opened for writing (user=%user.name command=%proc.cmdline parent=%proc.pname \
           pcmdline=%proc.pcmdline file=%fd.name program=%proc.name gparent=%proc.aname[2] \
           ggparent=%proc.aname[3] gggparent=%proc.aname[4] container_id=%container.id image=%container.image.repository)"
  priority: ERROR
  tags: [filesystem, mitre_persistence]
```

```lua
- macro: open_write
  condition: evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0
```


---

# Detect su, sudo
Rules

```lua
- rule: Detect su or sudo
  desc: detect sudo activities
  condition: >
    spawned_process
    and activity_under_escalated_privilege
    and not in (sre_known_infraops_actions, sre_known_managed_cloud_actions)
  output: >
    Privilege escalation activity (user=%user.name auser=%user.loginname command=%proc.cmdline ppid=%proc.ppid apid=%proc.apid pid=%proc.pid gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4] user_loginuid=%user.loginuid parent=%proc.pname pcmdline=%proc.pcmdline )
  priority: WARNING
  tags: [process, sudo, su]
```

```lua
- macro: activity_under_escalated_privilege
  condition: >
    proc.name in (sudo, su)
    or proc.pname in (sudo, su)
    or proc.aname[1] in (sudo, su)
    ...
```

```lua
- rule: Privilege escalation
  condition: sf.pproc.uid != 0 and sf.proc.uid = 0 and not entrypoint
```

--- 

# Compromised server process
Rules

HitchSQL injection attack?
```lua
condition: spawn_process and proc.name = mysqld and not proc_is_new
```

```lua
- macro: spawn_process
  condition: syscall.type = execve

- macro: proc_is_new
  condition: proc.duration <= 5000000000
```

---
layout: two-cols
---

# Howto rules
What we tweaked?

```yaml {2}
# override upstream defined macro
- macro: user_known_read_sensitive_files_activities
  condition: >
    (sre_authorized_activities)
```



```bash
rules/
├── falco_rules.preload.yaml
├── falco_rules-10-exceptions.yaml
├── falco_rules-20-security.yaml
├── falco_rules-30-apps.yaml
├── falco_rules-40-fim.yaml
└── falco_rules-50-cve.yaml
```


::right::

<br/>
<br/>
<br/>
<br/>
<br/>

- macro: `failed_k8s_annotation`
- macro: `sre|host|infra_authz_activities`
- macro: `sre|aws|gcp_known_vendoractions`
- macro: `sre_known_ports`
- list: `sre|aws|gcp_known_commands`
- list: ....


<!-- 
 (to avoid false-positive alerts)
-->

---
layout: default
---

# Falco sidekick

<!-- 
https://euangoddard.github.io/clipboard2markdown/
-->

Integrations

https://github.com/falcosecurity/falcosidekick

```yaml
alertmanager:
  hostport: http://{domain or ip}:{port}
  minimumpriority: "error"               # emergency|alert|critical|error|warning|notice|informational|debug
  endpoint: "/api/v2/alerts"
  expiresafter: "900"
```
<div>

[Slack](https://slack.com/)
<mdi-circle-small />   [Rocketchat](https://rocket.chat/)
<mdi-circle-small />   [Mattermost](https://mattermost.com/)
<mdi-circle-small />   [Teams](https://products.office.com/en-us/microsoft-teams/group-chat-software)
<mdi-circle-small />   [Datadog](https://www.datadoghq.com/)
<mdi-circle-small />   [Discord](https://www.discord.com/)
<mdi-circle-small />   [AlertManager](https://prometheus.io/docs/alerting/alertmanager/)
<mdi-circle-small />   [Elasticsearch](https://www.elastic.co/)
<mdi-circle-small />   [Loki](https://grafana.com/oss/loki)
<mdi-circle-small />   [NATS](https://nats.io/)
<mdi-circle-small />   [STAN (NATS Streaming)](https://docs.nats.io/nats-streaming-concepts/intro)
<mdi-circle-small />   [Influxdb](https://www.influxdata.com/products/influxdb-overview/)
<mdi-circle-small />   [AWS Lambda](https://aws.amazon.com/lambda/features/)
<mdi-circle-small />   [AWS SQS](https://aws.amazon.com/sqs/features/)
<mdi-circle-small />   [AWS SNS](https://aws.amazon.com/sns/features/)
<mdi-circle-small />   [AWS CloudWatch](https://aws.amazon.com/cloudwatch/features/)
<mdi-circle-small />   [AWS S3](https://aws.amazon.com/s3/features/)
<mdi-circle-small />   SMTP (email)
<mdi-circle-small />   [Opsgenie](https://www.opsgenie.com/)
<mdi-circle-small />   [StatsD](https://github.com/statsd/statsd)
<mdi-circle-small />   [DogStatsD](https://docs.datadoghq.com/developers/dogstatsd/?tab=go)
<mdi-circle-small />   Webhook
<mdi-circle-small />   [Azure Event Hubs](https://azure.microsoft.com/en-in/services/event-hubs/)
<mdi-circle-small />   [Prometheus](https://prometheus.io/)
<mdi-circle-small />   [GCP PubSub](https://cloud.google.com/pubsub)
<mdi-circle-small />   [GCP Storage](https://cloud.google.com/storage)
<mdi-circle-small />   [Google Chat](https://workspace.google.com/products/chat/)
<mdi-circle-small />   [Apache Kafka](https://kafka.apache.org/)
<mdi-circle-small />   [PagerDuty](https://pagerduty.com/)
<mdi-circle-small />   [Kubeless](https://kubeless.io/)
<mdi-circle-small />   [OpenFaaS](https://www.openfaas.com/)

</div>

<!--
- premapovali jsme severity
- strip cardinalities, syscall drops
- output formating -> alert description
-->

---
# Alertmanager integration
What we tweaked?

[falcosidekick/outputs/alertmanager.go](https://github.com/falcosecurity/falcosidekick/blob/master/outputs/alertmanager.go)

- remap falco.Priority to our Alertmanager expecrted severities
- output simplified, updated -> Alert.description (instead of `info` field)
- `alert_name != rule_name` (alerts prefixed by App name - k8s label annotation)
- strip cardinalities of syscall drops (in upstream)
- pass k8s annotations to alert
- pass OriginHost
- filter/drop based on k8s anotations

<!-- 
Dalsi integrace - with more lower priority -> short term search
-->

---

# Dashboards and alerting

<img src="/images/webui_03-s.png" class="m-0 fit center" />

<!-- Falcosidekick-ui >0.5.3, rewritten month ago -->

---

# Elasticsearch
Record detail

<img src="/images/es-event-detail-1.png" class="m-0 fit center" />

<!-- 
log/audit path -> ES -> archive

example with many details !
-->
---

# Falco Audit in Grafana

<img src="/images/grafana-audit-view-s.png" class="m-0 fit center" />

<!--
Custom dasshboards
-->

---
layout: two-cols
---

# Plugins

Addded recently (>= v0.31)

External sources
- API boundaries, hardly extensible
- Falco must expose a web server
- TLS to manage
- Doesnt work with managed K8s

Features
- dynamic shared libraries -> any language
- allows falco to collect and extract fields from streams of events
- source / extractor plugins

::right::
<br/>
<br/>
<br/>
<br/>
<br/>

Available plugins:
- K8s audit
- AWS CloudTrail
- JSON
- comming (okta, github, docker, seccompagent)

---
layout: two-cols
---

# K8s audit rules

https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit

An attempt to start a pod using the host pid NS.
```lua
condition: kevt and pod and kcreate
  and ka.req.pod.host_pid intersects (true) 
```

Detect pod starting a privileged container
```lua
condition: kevt 
  and pod
  and kcreate
  and ka.req.pod.containers.privileged intersects (true)
  and not ka.req.pod.containers.image.repository 
    in (falco_privileged_images)
```

::right::

<div class="m-2 pt-16">

Updated role binding
```lua
condition: kevt 
  and clusterrolebinding
  and kcreate and ka.req.binding.role=cluster-admin
```

Credentials in configmap
```lua
- macro: contains_private_credentials
  condition: >
   (ka.req.configmap.obj contains "access_key" or
    ka.req.configmap.obj contains "access-key" or
    ka.req.configmap.obj contains "token" or
    ka.req.configmap.obj contains "secret" or
    ka.req.configmap.obj contains "pass")
```
</div>

---
layout: default
---

# CloudTrail
Plugin

```lua
- rule: Console Login Without MFA
  desc: Detect a console login without MFA.
  condition:
    ct.name="ConsoleLogin" and not ct.error exists
    and ct.user.identitytype!="AssumedRole"
      and json.value[/responseElements/ConsoleLogin]="Success"
        and json.value[/additionalEventData/MFAUsed]="No"
  output:
    Detected a console login without MFA
    (requesting user=%ct.user,
     requesting IP=%ct.srcip,
     AWS region=%ct.region)
  priority: CRITICAL

```
<!--
Falco Cloudtrail plugin can read AWS Cloudtrail logs and emit events for each Cloudtrail log entry.
-->

---

# What is the next step?

```lua
- rule: Pet detection, custom plugin
  condition: video.entities[animal] > 0
```

Sysflow.io
```lua
- rule: Impair Defenses: Disable or Modify System Firewall
  desc: Detects disabling security tools
  condition: sf.opflags = EXEC and
             ((sf.proc.name in (service_cmds) and
               sf.proc.args pmatch (security_services) and sf.proc.args pmatch (stop_cmds)) or
             ( sf.proc.name = setenforce and sf.proc.args = '0'))
  prefilter: [PE]
```

```lua
- rule: Large network data transfer with database endpoint
  condition: ( sf.opflags contains RECV and sf.net.dport = 3306 and sf.flow.rbytes > 1024 ) or
             ( sf.opflags contains SEND and sf.net.sport = 3306 and sf.flow.wbytes > 1024 )
  prefilter: [NF]
```

```lua
- rule: Privilege escalation
  condition: sf.pproc.uid != 0 and sf.proc.uid = 0 and not entrypoint
```

<!-- 

- SRE anomaly detection (pyra, prometheus anomaly detection)

--

- Falco, beharvioural
- Sysflow, flows/coalescing (seskupovaniw)

-->

---

# SysFlow.io
cloud-native system telemetry framework

<img src="/images/sysflow-pipeline.png" class="m-10 tp-10 pr-15 center" />

<!--
ma byt - "kompaktni" open telemetry format 

umoznit provazat sytemove udalosti

semantically compressed system events

podobna architektura

(sumarizovat)

- Reduces data footprints drastically when compared to raw system call collection
- Reduces event fatigue (a.k.a. "too many alerts") 
- Provides useful context by linking together system event data at the data format level

compress system events
that records workload behaviors 
by connecting event and flow representations of process control flows, file interactions, and network communications

-->

---
layout: image-right
image: /images/sysflow-graphlet-2.png
---

# SysFlow.io

<img src="/images/sysflow-graphlet.png" class="center" />

- Rate modulation
- Node-level regulators
  - HyperLogLog sketch
  - Count-min sketch
  - Tries

<!-- 

- semantically reduce heavy hitters to minimize burst

- HyperLogLog - Approximates the number of distinct items in a multiset

- Count-min - Probabilistic frequency table of events

- Tries - Omezuje extensivni přístup k fs

-->

---
layout: two-cols
---

# Learn More

[Documentation](https://falco.org/docs/getting-started/) · [GitHub](https://github.com/falcosecurity) · [Blog](https://falco.org/blog/)

- [Falco & Plugins CloudNativeCon 2022](https://www.youtube.com/watch?v=tZI8Tzf1uzg)

- [SysFlow](https://sysflow.io/) is a cloud-native system telemetry framework that enables the creation of security analytics on a scalable, pluggable open-source platform

  - [SysFlow telemetry](https://github.com/sysflow-telemetry)
  - [SysFlow & Sidekick analytics](https://falco.org/blog/sysflow-falco-sidekick) PoC
  - [SysFlow policies](https://github.com/sysflow-telemetry/sf-processor/blob/master/docs/POLICIES.md) & [examples](https://github.com/sysflow-telemetry/sf-processor/blob/master/resources/policies/runtimeintegrity)


- Plugin [Pet surveillance with falco](https://sysdig.com/blog/pet-surveillance-falco) PoC 

- Employ AI/ML for anomaly detection

::right::

<img src="/qr.png" class="mt-20 pl-10 h-80" />

<!-- 
- [Kubescape](https://github.com/armosec/kubescape) \
  K8s open-source tool providing a multi-cloud K8s single pane of glass, including risk analysis, security compliance, RBAC visualizer and image vulnerabilities scanning
-->

---
layout: end
---

---
layout: default
---

# Backup slides
Falco architectural overview

![](/images/falco-architectural-overview.png)

---

# Backup slides
SysFlow architectural overview

<img src="/images/sysflow-arch.png" class="h-100 center" />

--- 

# Backup slides
eBPF network observability

![](/screenshots/ebpf-09.png)

<!-- 
- trace TCP connect/accept and UPD connect activity
- uses telemetry from eBPF sensor to augment audit events
- reverse DNS information..
-->

---
layout: center
---
# Backup slides
SysFlow.io integration to sidekick

<img src="/images/sysflow-falco-sidekick-ui.png" class="h-100 center" />

---

# Backup slides
AuditD comparison

<img src="/screenshots/ebpf-03.png" class="h-80 center" />

---

# Backup slides
Inbound ssh rule

```lua

- rule: Inbound SSH Connection
  desc: Detect Inbound SSH Connection
  condition: >
    ((evt.type in (accept,listen) and evt.dir=<) or
      (evt.type in (recvfrom,recvmsg))) and ssh_port
      and not is_kubernetes
  output: >
    Inbound SSH connection (user=%user.name client_ip=%fd.cip client_port=%fd.cport server_ip=%fd.sip)
  priority: WARNING
  tags: [ssh, network]

```

---

# Backup slides
K8s audit -> plugin

* Removed K8S audit logs from Falco [#1952] (https://github.com/falcosecurity/falco/pull/1952)
* Now under plugins: https://github.com/falcosecurity/plugins


```lua
- rule: Attach/Exec Pod
  desc: Detect any attempt to attach/exec to a pod
  condition: |
    kevt_started and pod_subresource and kcreate and ka.target.subresource in (exec,attach)
    and not user_known_exec_pod_activities
```

```lua
- list: falco_hostpid_images
  items: []

- rule: Create HostPid Pod
  desc: Detect an attempt to start a pod using the host pid namespace.
  condition: |
    kevt and pod and kcreate and ka.req.pod.host_pid intersects (true)
    and not ka.req.pod.containers.image.repository in (falco_hostpid_images)
```

---

# Backup slides
Rules from helm chart

https://github.com/falcosecurity/falco/tree/master/rules

```lua

  rules-traefik.yaml: |-
    - macro: traefik_consider_syscalls
      condition: (evt.num < 0)

    - macro: app_traefik
      condition: container and container.image startswith "traefik"

    # Restricting listening ports to selected set

    - list: traefik_allowed_inbound_ports_tcp
      items: [443, 80, 8080]
```

---

# Dashboards and alerting

<img src="/images/webui_01-b.png" class="m-0 fit" />

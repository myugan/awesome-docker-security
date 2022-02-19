# Awesome Docker Security [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

List of awesome resources about docker security included books, blogs, video, tools and cases.

## Table of Contents

  - [Books](#books)
  - [Blogs](#blogs)
  - [Videos](#videos)
  - [Tools](#tools)
  - [Cases](#cases)

## Books

- [Container Security by Liz Rice](https://learning.oreilly.com/library/view/container-security/9781492056690/)
- [Docker Security by Adrian Mouat](https://learning.oreilly.com/library/view/docker-security/9781492042297/)
- [Advanced Infrastructure Penetration Testing by Chiheb Chebbi](https://learning.oreilly.com/library/view/advanced-infrastructure-penetration/9781788624480/)

## Blogs

- [Docker Security](https://docs.docker.com/engine/security/)
- [OWASP Docker Security](https://github.com/OWASP/Docker-Security)
- [Introduction to Container Security Understanding the isolation properties of Docker](https://www.docker.com/sites/default/files/WP_IntrotoContainerSecurity_08.19.2016.pdf)
- [Anatomy of a hack: Docker Registry](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/)
- [Hunting for Insecure Docker Registries](https://medium.com/@act1on3/hunting-for-insecure-docker-registries-d87d293e6779)
- [How Abusing Docker API Lead to Remote Code Execution](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence_wp.pdf)
- [Using Docker-in-Docker for your CI or testing environment? Think twice](https://jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/)
- [Vulnerability Exploitation in Docker Container Environments](https://www.blackhat.com/docs/eu-15/materials/eu-15-Bettini-Vulnerability-Exploitation-In-Docker-Container-Environments-wp.pdf)
- [Mitigating High Severity RunC Vulnerability (CVE-2019-5736)](https://blog.aquasec.com/runc-vulnerability-cve-2019-5736)
- [Building Secure Docker Images - 101](https://medium.com/walmartlabs/building-secure-docker-images-101-3769b760ebfa)
- [Dockerfile Security Checks using OPA Rego Policies with Conftest](https://blog.madhuakula.com/dockerfile-security-checks-using-opa-rego-policies-with-conftest-32ab2316172f)
- [An Attacker Looks at Docker: Approaching Multi-Container Applications](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf)
- [Lesson 4: Hacking Containers Like A Boss ](https://www.practical-devsecops.com/lesson-4-hacking-containers-like-a-boss/)
- [How To Secure Docker Images With Encryption Through Containerd](https://www.whitesourcesoftware.com/free-developer-tools/blog/secure-docker-with-containerd/)

## Videos

- [Best practices for building secure Docker images](https://www.youtube.com/watch?v=LmUw2H6JgJo)
- [OWASP Bay Area - Attacking & Auditing Docker Containers Using Open Source tools](https://www.youtube.com/watch?v=ru7GicI5iyI)
- [DockerCon 2018 - Docker Container Security](https://www.youtube.com/watch?v=E_0vxpL_lxM)
- [DokcerCon 2019 - Container Security: Theory & Practice at Netflix](https://www.youtube.com/watch?v=bWXne3jRTf0)
- [DockerCon 2019 - Hardening Docker daemon with Rootless mode](https://www.youtube.com/watch?v=Qq78zfXUq18)
- [RSAConference 2019 - How I Learned Docker Security the Hard Way (So You Don’t Have To)](https://www.youtube.com/watch?v=C343TPOpTzU)
- [BSidesSF 2020 - Checking Your --privileged Container](https://www.youtube.com/watch?v=5VgSFRyI38w)
- [Live Container Hacking: Capture The Flag - Andrew Martin (Control Plane) vs Ben Hall (Katacoda)](https://www.youtube.com/watch?v=iWkiQk8Kdk8)

## Tools

### Container Runtime

- [gVisor](https://github.com/google/gvisor) - An application kernel, written in Go, that implements a substantial portion of the Linux system surface. 
- [Kata Container](https://github.com/kata-containers/kata-containers) - An open source project and community working to build a standard implementation of lightweight Virtual Machines (VMs) that feel and perform like containers, but provide the workload isolation and security advantages of VMs.  
- [sysbox](https://github.com/nestybox/sysbox) - An open-source container runtime that enables Docker containers to act as virtual servers capable of running software such as Systemd, Docker, and Kubernetes in them. Launch inner containers, knowing that the outer container is strongly isolated from the underlying host.
- [Firecracker](https://github.com/firecracker-microvm/firecracker-containerd) - An open source virtualization technology that is purpose-built for creating and managing secure, multi-tenant container and function-based services.

### Container Scanning

- [trivy](https://github.com/aquasecurity/trivy) - A simple and comprehensive Vulnerability Scanner for Containers, suitable for CI.
- [Clair](https://github.com/quay/clair) - Vulnerability Static Analysis to discovering Common Vulnerability Exposure (CVE) on containers and can integrate with CI like Gitlab CI which included on their [template](https://docs.gitlab.com/ee/user/application_security/container_scanning/).
- [Harbor](https://github.com/goharbor/harbor) - An open source trusted cloud native registry project that equipped with several features such as RESTful API, Registry, Vulnerability Scanning, RBAC and etc.
- [Anchore Engine](https://anchore.com) - An open source project that provides a centralized service for inspection, analysis and certification of container images. Access the engine through a RESTful API and Anchore CLI then integrated with your CI/CD pipeline.
- [grype](https://github.com/anchore/grype) - An open source project from Anchore to perform a vulnerability scanning for container images and filesystems.
- [Dagda](https://github.com/eliasgranderubio/dagda/) - A tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities.
- [Synk](https://snyk.io) - CLI and build-time tool to find & fix known vulnerabilities in open-source dependencies support container scanning, application security.

### Compliance

- [Docker Bench for Security](https://github.com/docker/docker-bench-security) - A script that checks for dozens of common best-practices around deploying Docker containers in production.
- [CIS Docker Benchmark - InSpec profile](https://github.com/dev-sec/cis-docker-benchmark) - Compliance profile implement the CIS Docker 1.13.0 Benchmark in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment
- [lynis](https://github.com/CISOfy/Lynis) - Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) - An open source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack.
- [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) - A policy-enabled authorization plugin for Docker. 

### Pentesting

- [BOtB](https://github.com/brompwnie/botb) - Container analysis and exploitation tool designed to be used by pentesters and engineers while also being CI/CD friendly with common CI/CD technologies.
- [Gorsair](https://github.com/Ullaakut/Gorsair) - A penetration testing tool for discovering and remotely accessing Docker APIs from vulnerable Docker containers.
- [Cloud Container Attack Tool](https://github.com/RhinoSecurityLabs/ccat) - A tool for testing security of container environments. 
- [DEEPCE](https://github.com/stealthcopter/deepce) - A tool for docker enumeration, escalation of privileges and container escapes. 

### Playground

- [DockerSecurityPlayground (DSP)](https://github.com/giper45/DockerSecurityPlayground) - A Microservices-based framework for the study of network security and penetration test techniques.
- [Katacoda Courses: Docker Security](https://www.katacoda.com/courses/docker-security) - Learn Docker Security using Interactive Browser-Based Scenarios.
- [Docker Security by Contol Plane](https://control-plane.io/training) - Learn Docker Security  from Control Plane.
- [Play with Docker](https://labs.play-with-docker.com/) - A simple, interactive, fun playground to learn Docker and its **free**.

### Monitoring

- [Falco](https://github.com/falcosecurity/falco) - Cloud Native Runtime Security.
- [Wazuh](https://wazuh.com) - Free, open source and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance.
- [Weave Scope](https://www.weave.works/oss/scope/) - Detects processes, containers, hosts. No kernel modules, no agents, no special libraries, no coding. Seamless integration with Docker, Kubernetes, DCOS and AWS ECS.

### Others

- [dive](https://github.com/wagoodman/dive) - A tool for exploring each layer in a docker image.
- [hadolint](https://github.com/hadolint/hadolint) - A smarter Dockerfile linter that helps you build best practice Docker images.
- [dockle](https://github.com/goodwithtech/dockle) - Container image linter, help you to build the best practices Docker image.
- [docker_auth](https://github.com/cesanta/docker_auth) - Authentication server for Docker Registry 2.
- [bane](https://github.com/genuinetools/bane) - Custom & better AppArmor profile generator for Docker containers.
- [secret-diver](https://github.com/cider-rnd/secret-diver) - Analyzes secrets in containers.
- [confine](https://github.com/shamedgh/confine) - Generate SECCOMP profiles for Docker images.
- [imgcrypt](https://github.com/containerd/imgcrypt) - OCI Image Encryption Package.
- [lazydocker](https://github.com/jesseduffield/lazydocker) - A tool to manage docker images and containers easily.

## Use Cases

- [How I Hacked Play-with-Docker and Remotely Ran Code on the Host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)
- [A hacking group is hijacking Docker systems with exposed API endpoints](https://www.zdnet.com/article/a-hacking-group-is-hijacking-docker-systems-with-exposed-api-endpoints/)
- [Hundreds of Vulnerable Docker Hosts Exploited by Cryptocurrency Miners](https://www.imperva.com/blog/hundreds-of-vulnerable-docker-hosts-exploited-by-cryptocurrency-miners/)
- [Cryptojacking worm compromised over 2,000 Docker hosts](https://www.helpnetsecurity.com/2019/10/18/cryptojacking-worm-docker/)
- [Docker API vulnerability allows hackers to mine Monero](https://www.scmagazineuk.com/docker-api-vulnerability-allows-hackers-mine-monero/article/1578021)
- [Docker Registry HTTP API v2 exposed in HTTP without authentication leads to docker images dumping and poisoning](https://hackerone.com/reports/347296)
- [How dangerous is Request Splitting, a vulnerability in Golang or how we found the RCE in Portainer and hacked Uber](https://medium.com/@andrewaeva_55205/how-dangerous-is-request-splitting-a-vulnerability-in-golang-or-how-we-found-the-rce-in-portainer-7339ba24c871)
- [Docker Registries Expose Hundreds of Orgs to Malware, Data Theft](https://threatpost.com/docker-registries-malware-data-theft/152734/)
- [Doki Backdoor Infiltrates Docker Servers in the Cloud](https://threatpost.com/doki-backdoor-docker-servers-cloud/157871/)
- [Threat Actors Now Target Docker via Container Escape Features](https://www.trendmicro.com/en_us/research/21/b/threat-actors-now-target-docker-via-container-escape-features.html)
- [CVE-2020-15157: Vulnerability in Containerd Can Leak Cloud Credentials](https://blog.aquasec.com/cve-2020-15157-containerd-container-vulnerability)

## [Contributing](contributing.md)

Your contributions are always welcome.

## License

[![CC0](https://i.creativecommons.org/p/zero/1.0/88x31.png)](https://creativecommons.org/publicdomain/zero/1.0/)
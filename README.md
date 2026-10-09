<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.4-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp%20%2B%20dnspython-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-subdomain-takeover/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-subdomain-takeover</h1>
<p align="center"><em>Subdomain Takeover Vulnerability Scanner — VampSecure Labs</em></p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

### Overview

**vamp-subdomain-takeover** detects subdomain takeover vulnerabilities by performing full CNAME chain resolution and comparing dangling DNS records against a fingerprint database of 30+ cloud services and hosting platforms.

A subdomain takeover occurs when a subdomain's DNS CNAME points to a cloud resource (GitHub Pages, AWS S3, Heroku, Netlify, etc.) that no longer exists, allowing an attacker to register that resource and serve content under the victim's domain. This vulnerability class directly enables phishing, session hijacking, and content injection.

The scanner classifies each result into three states: **VULNERABLE** (fingerprint confirmed in HTTP response body), **POTENTIAL** (orphaned CNAME detected, HTTP confirmation not possible), or **SAFE**.

### Features

- Asynchronous CNAME chain resolution via `dns.asyncresolver` — handles multi-hop delegation
- 30+ service fingerprint signatures covering major cloud platforms
- Dual-stage validation: DNS orphan detection followed by HTTP body fingerprint confirmation
- CVSS scores embedded per service (GitHub Pages 8.1, AWS S3 9.3, Heroku 8.8, Netlify 8.8, Vercel 8.8, Azure 8.5, and more)
- Scope-aware: scan all subdomains for a domain, or supply a custom subdomain list
- Filter output to vulnerable hosts only with `--only-vulnerable`
- Configurable concurrency for large-scale scans

### Requirements

```
Python 3.11+
aiohttp >= 3.9.0
dnspython >= 2.4.0
rich >= 13.7.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Installation

```bash
pip install vamp-subdomain-takeover
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-subdomain-takeover
```

```bash
git clone https://github.com/belky-me/vamp-subdomain-takeover.git
cd vamp-subdomain-takeover
pip install -r requirements.txt
```

### Usage

```
python vamp_subdomain_takeover.py -d DOMAIN [OPTIONS]

Required:
  -d, --domain DOMAIN            Apex domain to check (drives auto-enumeration if no list given)

Input:
  -f, --from-file FILE           File with subdomains to check (one per line)
      --subdomains SUB1,SUB2     Comma-separated subdomain list

Output:
  -o, --output FILE              Write findings to JSON
      --html FILE                Generate standalone HTML report
      --only-vulnerable          Output only VULNERABLE results (suppress POTENTIAL/SAFE)

Performance:
      --concurrency N            Concurrent DNS + HTTP workers (default: 30)
      --http-timeout N           HTTP response timeout in seconds (default: 12)
```

### Examples

Check all subdomains of a target domain discovered via passive recon:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt
```

Check a domain and write only confirmed vulnerable findings to JSON:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt \
  --only-vulnerable -o takeover_findings.json
```

Generate an HTML report for client delivery:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdomains.txt --html report.html
```

Check specific subdomains with reduced concurrency for rate-limited resolvers:

```bash
python vamp_subdomain_takeover.py -d example.com \
  --subdomains staging,dev,old,mail,legacy \
  --concurrency 10 -o findings.json
```

### Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich table with subdomain, CNAME chain, service, status, and CVSS |
| JSON | `-o FILE` | Full structured output: DNS chain, service, status, evidence |
| HTML | `--html FILE` | Standalone dark-theme report for client delivery or archival |

### Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | All subdomains safe — no takeover risk detected | Pass gate |
| `1` | POTENTIAL findings — orphaned CNAMEs without HTTP confirmation | Review recommended |
| `2` | VULNERABLE — confirmed takeover opportunity detected | Fail gate — remediate immediately |

### Status Levels

| Status | Meaning |
|--------|---------|
| `VULNERABLE` | Fingerprint string found in HTTP response body — takeover confirmed |
| `POTENTIAL` | CNAME points to unclaimed resource but HTTP probe inconclusive |
| `SAFE` | CNAME target is registered and responds normally |
| `ERROR` | DNS resolution failed or host unreachable |

### Sample Output

```
$ python vamp_subdomain_takeover.py -d example.com -f subdomains.txt
vamp-subdomain-takeover v1.2 — VampSecure Labs
──────────────────────────────────────────────────────────────────────
[*] Checking 48 subdomains for example.com with concurrency 30...

┌─────────────────────┬────────────────────────────────────┬────────────┬───────────┬──────┐
│ Subdomain           │ CNAME Chain                        │ Service    │ Status    │ CVSS │
├─────────────────────┼────────────────────────────────────┼────────────┼───────────┼──────┤
│ shop.example.com    │ → shop.example.myshopify.com       │ Shopify    │ SAFE      │ —    │
│ blog.example.com    │ → example.github.io (DANGLING)     │ GitHub Pgs │ VULNERABLE│ 8.1  │
│ cdn.example.com     │ → example.s3.amazonaws.com (NXDOM) │ AWS S3     │ VULNERABLE│ 9.3  │
│ staging.example.com │ → example-app.herokuapp.com        │ Heroku     │ POTENTIAL │ 8.8  │
│ mail.example.com    │ (no CNAME)                         │ —          │ SAFE      │ —    │
└─────────────────────┴────────────────────────────────────┴────────────┴───────────┴──────┘

Summary: 48 subdomains · 2 VULNERABLE · 1 POTENTIAL · 45 SAFE
Exit code: 2 — immediate remediation required

VULNERABLE — blog.example.com (GitHub Pages, CVSS 8.1)
  CNAME: blog.example.com → example.github.io
  HTTP body: "There isn't a GitHub Pages site here."
  Remediation: create repo at github.com/example OR remove DNS record

VULNERABLE — cdn.example.com (AWS S3, CVSS 9.3)
  CNAME: cdn.example.com → example.s3.amazonaws.com
  DNS: NXDOMAIN — bucket does not exist
  Remediation: create S3 bucket "example" OR remove DNS record
```

### Why vamp-subdomain-takeover vs. subjack · nuclei (takeover templates) · can-i-take-over-xyz

| Capability | vamp-subdomain-takeover | subjack | nuclei (takeover) | can-i-take-over-xyz |
|------------|------------------------|---------|-------------------|---------------------|
| Async CNAME chain resolution (multi-hop) | ✅ `dns.asyncresolver` | ✅ | ✅ | ❌ Reference only |
| HTTP body fingerprint confirmation | ✅ Dual-stage validation | ✅ | ✅ | ❌ |
| CVSS score per service | ✅ Embedded per finding | ❌ | ❌ | ❌ |
| MX / NS record checks | ✅ | ❌ | ❌ | ❌ |
| Continuous monitoring mode | ✅ | ❌ | ❌ via cron | ❌ |
| Standalone HTML report for client delivery | ✅ `--html` | ❌ | ✅ SARIF | ❌ |
| JSON structured output | ✅ | ✅ | ✅ | ❌ |
| Configurable concurrency | ✅ `--concurrency N` | ✅ | ✅ | ❌ |
| Python importable package | ✅ | ❌ Go | ❌ Go | ❌ |
| Self-hosted / no cloud dependency | ✅ | ✅ | ✅ | ❌ Web app |

- **CVSS scores per service** — each fingerprint carries a published CVSS base score (GitHub Pages 8.1, AWS S3 9.3, Azure CDN 8.5), giving clients an immediate risk priority without extra research.
- **Dual-stage validation** — DNS orphan detection alone produces false positives; the HTTP body fingerprint confirmation step verifies whether the unclaimed resource is actually exploitable.
- **MX and NS coverage** — email subdomain takeovers (via orphaned MX records) and DNS delegation hijacks (via abandoned NS records) are checked alongside CNAME takeovers.
- **Client-ready output** — `--html` produces a standalone dark-theme report with CVSS-sorted findings, ready to hand to a client without post-processing.

### Check Coverage

| Check | Service / Attack Vector | CVSS | Standard |
|-------|------------------------|------|----------|
| GitHub Pages CNAME orphan | `github.io` NXDOMAIN / "There isn't a GitHub Pages site here." | 8.1 | OWASP OTG-CONFIG-002 |
| AWS S3 bucket CNAME orphan | `s3.amazonaws.com` NXDOMAIN | 9.3 | MITRE ATT&CK T1584.001 |
| Heroku CNAME orphan | `herokuapp.com` "No such app" fingerprint | 8.8 | OWASP OTG-CONFIG-002 |
| Netlify CNAME orphan | `netlify.app` "Not Found" body fingerprint | 8.8 | OWASP OTG-CONFIG-002 |
| Vercel CNAME orphan | `vercel.app` "The deployment could not be found" | 8.8 | OWASP OTG-CONFIG-002 |
| Azure CDN / Blob orphan | `azurewebsites.net` / `blob.core.windows.net` NXDOMAIN | 8.5 | MITRE ATT&CK T1584.001 |
| Fastly CNAME orphan | `fastly.net` "Fastly error: unknown domain" | 7.5 | OWASP OTG-CONFIG-002 |
| Shopify CNAME orphan | `myshopify.com` "Sorry, this shop is currently unavailable" | 7.5 | OWASP OTG-CONFIG-002 |
| Tumblr CNAME orphan | `tumblr.com` "There's nothing here" body fingerprint | 7.2 | OWASP OTG-CONFIG-002 |
| Ghost / HelpScout / Zendesk orphan | Various SaaS "page not found" fingerprints | 7.0–7.5 | OWASP OTG-CONFIG-002 |
| Orphaned NS delegation (DNS hijack) | NS record pointing to unregistered domain | 9.0 | MITRE ATT&CK T1584.002 |
| Orphaned MX record (email takeover) | MX pointing to unclaimed mail host | 8.0 | MITRE ATT&CK T1584.001 |

### Part of VampSecure Labs Toolkit

`vamp-subdomain-takeover` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Multi-tool assessment orchestrator |

### Version History

| Version | Main changes |
|---------|-------------|
| v1.4 | Bilingual README (EN/ES) |
| v1.3 | Continuous monitoring mode |
| v1.1 | Initial release |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---
---

<a name="español"></a>
## 🇪🇸 Español

### Descripción general

**vamp-subdomain-takeover** detecta vulnerabilidades de subdomain takeover realizando resolución completa de cadenas CNAME y comparando registros DNS huérfanos contra una base de datos de firmas de más de 30 servicios cloud y plataformas de hosting.

Un subdomain takeover ocurre cuando el CNAME DNS de un subdominio apunta a un recurso cloud (GitHub Pages, AWS S3, Heroku, Netlify, etc.) que ya no existe, lo que permite a un atacante registrar ese recurso y servir contenido bajo el dominio de la víctima. Esta clase de vulnerabilidad habilita directamente phishing, hijacking de sesión e inyección de contenido.

El escáner clasifica cada resultado en tres estados: **VULNERABLE** (huella confirmada en el cuerpo de la respuesta HTTP), **POTENTIAL** (CNAME huérfano detectado, confirmación HTTP no posible) o **SAFE**.

### Características

- Resolución asíncrona de cadenas CNAME mediante `dns.asyncresolver` — gestiona delegación multi-salto
- Más de 30 firmas de servicio que cubren las principales plataformas cloud
- Validación en dos etapas: detección de huérfano DNS seguida de confirmación por huella en el cuerpo HTTP
- Scores CVSS embebidos por servicio (GitHub Pages 8.1, AWS S3 9.3, Heroku 8.8, Netlify 8.8, Vercel 8.8, Azure 8.5 y más)
- Consciencia de alcance: escanea todos los subdominios de un dominio, o proporciona una lista personalizada
- Filtrar salida solo a hosts vulnerables con `--only-vulnerable`
- Concurrencia configurable para escaneos a gran escala

### Requisitos

```
Python 3.11+
aiohttp >= 3.9.0
dnspython >= 2.4.0
rich >= 13.7.0
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

### Instalación

```bash
pip install vamp-subdomain-takeover
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-subdomain-takeover
```

```bash
git clone https://github.com/belky-me/vamp-subdomain-takeover.git
cd vamp-subdomain-takeover
pip install -r requirements.txt
```

### Uso

```
python vamp_subdomain_takeover.py -d DOMINIO [OPCIONES]

Obligatorio:
  -d, --domain DOMINIO           Dominio apex a comprobar (activa la enumeración automática si no se da lista)

Entrada:
  -f, --from-file FICHERO        Fichero con subdominios a comprobar (uno por línea)
      --subdomains SUB1,SUB2     Lista de subdominios separados por comas

Salida:
  -o, --output FICHERO           Escribir hallazgos en JSON
      --html FICHERO             Generar informe HTML standalone
      --only-vulnerable          Mostrar solo resultados VULNERABLE (suprimir POTENTIAL/SAFE)

Rendimiento:
      --concurrency N            Workers DNS + HTTP concurrentes (por defecto: 30)
      --http-timeout N           Timeout de respuesta HTTP en segundos (por defecto: 12)
```

### Ejemplos

Comprobar todos los subdominios de un dominio objetivo descubiertos mediante reconocimiento pasivo:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdominios.txt
```

Comprobar un dominio y escribir solo los hallazgos vulnerables confirmados en JSON:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdominios.txt \
  --only-vulnerable -o hallazgos_takeover.json
```

Generar un informe HTML para entrega al cliente:

```bash
python vamp_subdomain_takeover.py -d example.com -f subdominios.txt --html informe.html
```

Comprobar subdominios específicos con concurrencia reducida para resolvers con rate-limit:

```bash
python vamp_subdomain_takeover.py -d example.com \
  --subdomains staging,dev,old,mail,legacy \
  --concurrency 10 -o hallazgos.json
```

### Formatos de salida

| Formato | Cómo activarlo | Descripción |
|---------|----------------|-------------|
| Consola | Por defecto | Tabla Rich con subdominio, cadena CNAME, servicio, estado y CVSS |
| JSON | `-o FICHERO` | Salida estructurada completa: cadena DNS, servicio, estado, evidencia |
| HTML | `--html FICHERO` | Informe dark-theme standalone para entrega al cliente o archivo |

### Exit codes

| Código | Significado | Uso CI/CD |
|--------|-------------|-----------|
| `0` | Todos los subdominios seguros — sin riesgo de takeover detectado | Puerta de paso |
| `1` | Hallazgos POTENTIAL — CNAMEs huérfanos sin confirmación HTTP | Revisión recomendada |
| `2` | VULNERABLE — oportunidad de takeover confirmada | Puerta de fallo — remediar inmediatamente |

### Niveles de estado

| Estado | Significado |
|--------|-------------|
| `VULNERABLE` | Cadena de huella encontrada en el cuerpo de la respuesta HTTP — takeover confirmado |
| `POTENTIAL` | El CNAME apunta a un recurso no reclamado pero la sonda HTTP no es concluyente |
| `SAFE` | El objetivo del CNAME está registrado y responde con normalidad |
| `ERROR` | Resolución DNS fallida o host inaccesible |

### Salida de ejemplo

```
$ python vamp_subdomain_takeover.py -d example.com -f subdominios.txt
vamp-subdomain-takeover v1.2 — VampSecure Labs
──────────────────────────────────────────────────────────────────────
[*] Comprobando 48 subdominios de example.com con concurrencia 30...

┌─────────────────────┬────────────────────────────────────┬────────────┬───────────┬──────┐
│ Subdominio          │ Cadena CNAME                       │ Servicio   │ Estado    │ CVSS │
├─────────────────────┼────────────────────────────────────┼────────────┼───────────┼──────┤
│ shop.example.com    │ → shop.example.myshopify.com       │ Shopify    │ SAFE      │ —    │
│ blog.example.com    │ → example.github.io (DANGLING)     │ GitHub Pgs │ VULNERABLE│ 8.1  │
│ cdn.example.com     │ → example.s3.amazonaws.com (NXDOM) │ AWS S3     │ VULNERABLE│ 9.3  │
│ staging.example.com │ → example-app.herokuapp.com        │ Heroku     │ POTENTIAL │ 8.8  │
│ mail.example.com    │ (sin CNAME)                        │ —          │ SAFE      │ —    │
└─────────────────────┴────────────────────────────────────┴────────────┴───────────┴──────┘

Resumen: 48 subdominios · 2 VULNERABLE · 1 POTENTIAL · 45 SAFE
Exit code: 2 — remediación inmediata requerida

VULNERABLE — blog.example.com (GitHub Pages, CVSS 8.1)
  CNAME: blog.example.com → example.github.io
  Cuerpo HTTP: "There isn't a GitHub Pages site here."
  Remediación: crear repo en github.com/example O eliminar el registro DNS

VULNERABLE — cdn.example.com (AWS S3, CVSS 9.3)
  CNAME: cdn.example.com → example.s3.amazonaws.com
  DNS: NXDOMAIN — el bucket no existe
  Remediación: crear bucket S3 "example" O eliminar el registro DNS
```

### Por qué vamp-subdomain-takeover vs. subjack · nuclei (templates de takeover) · can-i-take-over-xyz

| Capacidad | vamp-subdomain-takeover | subjack | nuclei (takeover) | can-i-take-over-xyz |
|-----------|------------------------|---------|-------------------|---------------------|
| Resolución asíncrona de cadena CNAME (multi-salto) | ✅ `dns.asyncresolver` | ✅ | ✅ | ❌ Solo referencia |
| Confirmación por huella en cuerpo HTTP | ✅ Validación en dos etapas | ✅ | ✅ | ❌ |
| Score CVSS por servicio | ✅ Embebido por hallazgo | ❌ | ❌ | ❌ |
| Checks de registros MX / NS | ✅ | ❌ | ❌ | ❌ |
| Modo de monitorización continua | ✅ | ❌ | ❌ via cron | ❌ |
| Informe HTML standalone para entrega a cliente | ✅ `--html` | ❌ | ✅ SARIF | ❌ |
| Salida JSON estructurada | ✅ | ✅ | ✅ | ❌ |
| Concurrencia configurable | ✅ `--concurrency N` | ✅ | ✅ | ❌ |
| Paquete Python importable | ✅ | ❌ Go | ❌ Go | ❌ |
| Self-hosted / sin dependencia cloud | ✅ | ✅ | ✅ | ❌ Web app |

- **Scores CVSS por servicio** — cada huella lleva un score CVSS base publicado (GitHub Pages 8.1, AWS S3 9.3, Azure CDN 8.5), dando a los clientes una prioridad de riesgo inmediata sin investigación adicional.
- **Validación en dos etapas** — la detección de huérfanos DNS sola produce falsos positivos; el paso de confirmación por huella en el cuerpo HTTP verifica si el recurso no reclamado es realmente explotable.
- **Cobertura MX y NS** — los takeovers de subdominios de correo (vía registros MX huérfanos) y los hijacks de delegación DNS (vía registros NS abandonados) se comprueban junto con los takeovers CNAME.
- **Salida lista para cliente** — `--html` produce un informe dark-theme standalone con hallazgos ordenados por CVSS, listo para entregar al cliente sin postprocesado.

### Cobertura de checks

| Check | Servicio / Vector de ataque | CVSS | Estándar |
|-------|-----------------------------|------|----------|
| CNAME huérfano GitHub Pages | `github.io` NXDOMAIN / "There isn't a GitHub Pages site here." | 8.1 | OWASP OTG-CONFIG-002 |
| CNAME huérfano bucket AWS S3 | `s3.amazonaws.com` NXDOMAIN | 9.3 | MITRE ATT&CK T1584.001 |
| CNAME huérfano Heroku | `herokuapp.com` huella "No such app" | 8.8 | OWASP OTG-CONFIG-002 |
| CNAME huérfano Netlify | `netlify.app` huella "Not Found" en cuerpo | 8.8 | OWASP OTG-CONFIG-002 |
| CNAME huérfano Vercel | `vercel.app` "The deployment could not be found" | 8.8 | OWASP OTG-CONFIG-002 |
| Huérfano Azure CDN / Blob | `azurewebsites.net` / `blob.core.windows.net` NXDOMAIN | 8.5 | MITRE ATT&CK T1584.001 |
| CNAME huérfano Fastly | `fastly.net` "Fastly error: unknown domain" | 7.5 | OWASP OTG-CONFIG-002 |
| CNAME huérfano Shopify | `myshopify.com` "Sorry, this shop is currently unavailable" | 7.5 | OWASP OTG-CONFIG-002 |
| CNAME huérfano Tumblr | `tumblr.com` huella "There's nothing here" en cuerpo | 7.2 | OWASP OTG-CONFIG-002 |
| Huérfano Ghost / HelpScout / Zendesk | Varias huellas SaaS "page not found" | 7.0–7.5 | OWASP OTG-CONFIG-002 |
| Delegación NS huérfana (hijack DNS) | Registro NS apuntando a dominio no registrado | 9.0 | MITRE ATT&CK T1584.002 |
| Registro MX huérfano (takeover de correo) | MX apuntando a host de correo no reclamado | 8.0 | MITRE ATT&CK T1584.001 |

### Parte del toolkit de VampSecure Labs

`vamp-subdomain-takeover` forma parte del **Toolkit de Investigación de Seguridad de VampSecure Labs** — una colección de herramientas de evaluación de seguridad de grado profesional y auto-alojadas.

| Herramienta | Propósito |
|-------------|-----------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Escáner CVE de dispositivos edge multi-fabricante |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | Inteligencia CVE y motor RBVM |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Reconocimiento pasivo y mapeo de superficie de ataque |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Escáner de vulnerabilidades de subdomain takeover |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Enumerador de buckets de almacenamiento cloud |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Orquestador de evaluaciones multi-herramienta |

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.4 | README bilingüe (EN/ES) |
| v1.3 | Modo de monitorización continua |
| v1.1 | Versión inicial |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  Uso exclusivo en evaluaciones de seguridad autorizadas. El uso no autorizado está prohibido.
</p>

# INE-Cybersecurity-Certifications-Guide

> Guía de estudio personal para las certificaciones de **INE Security** (eLearnSecurity),
> organizada por área de conocimiento y por certificación. Cada módulo contiene notas,
> metodología, herramientas, prácticas de laboratorio y chuletas de referencia.

> ⚠️ **Proyecto de estudio personal.** Este repositorio no está afiliado ni respaldado por
> INE Security. No contiene material de examen ni contenido protegido por NDA: son apuntes
> propios y enlaces a documentación pública.

---

## Áreas y certificaciones

| Área | Carpeta | Certificaciones |
|---|---|---|
| Fundamentos | [`01-Fundamentals/`](01-Fundamentals) | [eJPT](01-Fundamentals/eJPT) · [eEDA](01-Fundamentals/eEDA) |
| Red Team | [`02-RedTeam/`](02-RedTeam) | [eCPPT](02-RedTeam/eCPPT) · [eWPT](02-RedTeam/eWPT) · [eWPTXv2](02-RedTeam/eWPTXv2) · [eMAPT](02-RedTeam/eMAPT) |
| Blue Team | [`03-BlueTeam/`](03-BlueTeam) | [eSOC](03-BlueTeam/eSOC) · [eCIR](03-BlueTeam/eCIR) · [eCDFP](03-BlueTeam/eCDFP) |
| Tecnologías emergentes | [`04-Emerging-Technologies/`](04-Emerging-Technologies) | [eAIS](04-Emerging-Technologies/eAIS) · [eIAMA](04-Emerging-Technologies/eIAMA) |

| Certificación | Nombre completo | Ruta del módulo |
|---|---|---|
| eJPT | Junior Penetration Tester | [`01-Fundamentals/eJPT`](01-Fundamentals/eJPT/README.md) |
| eEDA | Enterprise Defense Administrator | [`01-Fundamentals/eEDA`](01-Fundamentals/eEDA/README.md) |
| eCPPT | Certified Professional Penetration Tester | [`02-RedTeam/eCPPT`](02-RedTeam/eCPPT/README.md) |
| eWPT | Web Application Penetration Tester | [`02-RedTeam/eWPT`](02-RedTeam/eWPT/README.md) |
| eWPTXv2 | Web Application Penetration Tester eXtreme | [`02-RedTeam/eWPTXv2`](02-RedTeam/eWPTXv2/README.md) |
| eMAPT | Mobile Application Penetration Tester | [`02-RedTeam/eMAPT`](02-RedTeam/eMAPT/README.md) |
| eSOC | SOC Analyst | [`03-BlueTeam/eSOC`](03-BlueTeam/eSOC/README.md) |
| eCIR | Certified Incident Responder | [`03-BlueTeam/eCIR`](03-BlueTeam/eCIR/README.md) |
| eCDFP | Certified Digital Forensics Professional | [`03-BlueTeam/eCDFP`](03-BlueTeam/eCDFP/README.md) |
| eAIS | AI Security | [`04-Emerging-Technologies/eAIS`](04-Emerging-Technologies/eAIS/README.md) |
| eIAMA | Identity and Access Management Architect | [`04-Emerging-Technologies/eIAMA`](04-Emerging-Technologies/eIAMA/README.md) |

---

## Estructura del repositorio

Cada certificación sigue la misma convención de carpetas:

```
INE-Cybersecurity-Certifications-Guide/
├── 01-Fundamentals/          # eJPT, eEDA
├── 02-RedTeam/               # eCPPT, eWPT, eWPTXv2, eMAPT
├── 03-BlueTeam/              # eSOC, eCIR, eCDFP
├── 04-Emerging-Technologies/ # eAIS, eIAMA
├── resources/                # enlaces, lecturas, vídeos y consejos
├── scripts/                  # automatización y utilidades
├── README.md
├── CONTRIBUTING.md
├── LICENSE
└── .gitignore
```

Dentro de cada módulo de certificación:

| Carpeta | Contenido |
|---|---|
| `methodology/` | Fases y procedimientos numerados (`01-…`, `02-…`) |
| `tools/` | Referencias de herramientas, guías y scripts propios |
| `labs/` | Montaje de laboratorios, escenarios y ejercicios prácticos |
| `cheatsheets/` | Chuletas de comandos y terminología de consulta rápida |

---

## Recursos y scripts

- [`resources/official-links.md`](resources/official-links.md) — enlaces oficiales de INE Security.
- [`resources/recommended-reading.md`](resources/recommended-reading.md) — lecturas recomendadas.
- [`resources/video-tutorials.md`](resources/video-tutorials.md) — tutoriales en vídeo.
- [`resources/study-tips.md`](resources/study-tips.md) — consejos de estudio.
- [`scripts/automation/env-setup.sh`](scripts/automation/env-setup.sh) — instalación básica del entorno.
- [`scripts/automation/tool-installer.py`](scripts/automation/tool-installer.py) — instalador de herramientas.
- [`scripts/utilities/report-generator.py`](scripts/utilities/report-generator.py) — generador de informes de progreso.

---

## Estado del proyecto

- [x] Estructura inicial del repositorio
- [ ] Contenido de cada módulo (marcadores `- [ ]` / TODO dentro de cada nota)
- [ ] Añadir guías de laboratorio reproducibles por certificación

Consulta [`CONTRIBUTING.md`](CONTRIBUTING.md) si quieres colaborar o ampliar notas.

## Licencia

Distribuido bajo la licencia **MIT**. Ver [`LICENSE`](LICENSE).

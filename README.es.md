# Guía de Certificaciones de Ciberseguridad de INE

[![Licencia: MIT](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](LICENSE)
[![Contenido: inglés](https://img.shields.io/badge/Contenido-ingl%C3%A9s-blue.svg)](README.md)
[![INE Security: no oficial](https://img.shields.io/badge/INE%20Security-no%20oficial-lightgrey.svg)](README.md)

> 🇬🇧 **[English version](README.md)** · 🇪🇸 Estás leyendo la portada en español. El contenido
> de los módulos está en inglés; esta página sirve para orientarte y enlazar cada guía.

> ## ⚠️ Proyecto personal, no afiliado a INE Security
>
> Este repositorio es un **proyecto de estudio personal e independiente**. **No está
> afiliado, patrocinado ni respaldado por INE Security** (antes eLearnSecurity). Contiene
> únicamente notas de estudio originales del autor y enlaces a documentación pública.
> **No hay preguntas de examen, respuestas, dumps ni material protegido por NDA** de INE ni
> de ningún otro proveedor.
>
> Los nombres de certificaciones son marcas de sus titulares y se usan solo para describir
> de qué trata cada guía. Para cualquier dato autoritativo —temario, formato del examen,
> precio, inscripción— usa siempre **https://ine.com/certifications**.

## 📅 Última verificación contra el catálogo público de INE: **18 de septiembre de 2026**

Ese día se comprobó cada nombre, cada página de producto y cada anuncio de versión que cita
la guía, contra las páginas de INE: las doce páginas de producto respondieron **HTTP 200**,
se enumeró el sitemap de INE para confirmar que esas doce son todo el portfolio de seguridad
y cada nota de versión se contrastó con la página que la anuncia. Lo que **no** cubre esa
fecha: la logística del examen (número de preguntas, duración, precio, nota de corte, listas
oficiales de dominios). Cambia a menudo y **no** se reproduce aquí a propósito: cada módulo
enlaza la página oficial en su lugar.

**Nota de mantenimiento.** La guía se mantiene con el mejor esfuerzo posible y sin
compromiso de seguir todos los cambios de INE. Si la fecha de arriba tiene más de unos
meses, trata los datos de versión como no verificados y consulta primero
**https://ine.com/certifications** y **https://ine.com/newsroom**.

## Qué encontrarás

Doce módulos de estudio, cada uno autónomo, organizados por área de conocimiento. Cada
módulo incluye metodología por fases, referencias de herramientas, laboratorios prácticos y
cheatsheets.

### Fundamentos

| Certificación | Nombre oficial | Qué prueba |
|---|---|---|
| [eJPT](01-Fundamentals/eJPT/README.md) | Junior Penetration Tester | Ejecutar un pentest pequeño de principio a fin sobre máquinas reales, con evidencia. |

### Red Team

| Certificación | Nombre oficial | Qué prueba |
|---|---|---|
| [eCPPT](02-RedTeam/eCPPT/README.md) | Certified Professional Penetration Tester | Moverte en una red corporativa: Active Directory, pivoting, escalada, informe. |
| [eWPT](02-RedTeam/eWPT/README.md) | Web Application Penetration Tester | Encontrar y explotar vulnerabilidades web con método. |
| [eWPTX](02-RedTeam/eWPTX/README.md) | Web Application Penetration Tester eXtreme | Encadenar fallos web y saltarte los controles que los protegen. |
| [eMAPT](02-RedTeam/eMAPT/README.md) | Mobile Application Penetration Tester | Evaluar aplicaciones Android e iOS: tráfico, almacenamiento, lógica y código. |

### Blue Team

| Certificación | Nombre oficial | Qué prueba |
|---|---|---|
| [eEDA](03-BlueTeam/eEDA/README.md) | Enterprise Defense Administrator | Administrar defensas: gobierno, riesgo, cumplimiento, hardening y evidencia. |
| [eSOC](03-BlueTeam/eSOC/README.md) | SOC Analyst | Triar alertas e investigar en Tier 1: qué ha saltado, si es real, qué toca. |
| [eCIR](03-BlueTeam/eCIR/README.md) | Certified Incident Responder | Llevar un incidente completo: preservar, contener, erradicar, recuperar, comunicar. |
| [eCDFP](03-BlueTeam/eCDFP/README.md) | Certified Digital Forensics Professional | Adquirir, analizar y documentar evidencia digital defendible. |
| [eCTHP](03-BlueTeam/eCTHP/README.md) | Certified Threat Hunting Professional | Cazar de forma proactiva lo que la detección no vio y convertirlo en detecciones. |

### Tecnologías emergentes

| Certificación | Nombre oficial | Qué prueba |
|---|---|---|
| [eAIS](04-Emerging-Technologies/eAIS/README.md) | AI Systems Security Specialist | Entender la superficie de ataque de sistemas de IA, probarla y defenderla. |
| [eIAMA](04-Emerging-Technologies/eIAMA/README.md) | Certified Identity & Access Management Technologist | Implantar y operar gestión de identidades y accesos, y razonar su arquitectura. |

Todas las certificaciones enlazan su **página de producto verificada**. Este repositorio
**nunca inventa** una URL profunda: un slug equivocado parece oficial y lleva a otro sitio.
El catálogo completo de INE, que incluye también sus certificaciones no relacionadas con
seguridad, está en **https://ine.com/certifications**.

## Certificaciones retiradas por INE

Estas credenciales **ya no se ofrecen ni se pueden examinar**. Se listan aquí para que
puedas situar el material antiguo que encuentres por ahí: **no prepares ninguna de ellas** y
desconfía de quien siga vendiendo formación "oficial" para ellas.

| Credencial | Nombre que usó INE | Retirada |
|---|---|---|
| eCPTXv2 / PTX v2 | Penetration Testing Extreme | 1 oct 2023 |
| eCMAP / Map v1 | Malware Analysis Professional | 1 oct 2023 |
| eCXD / XDS v1 | Exploit Development Student | 1 oct 2023 |
| eCRE / REP v1 | Reverse Engineering Professional | 1 oct 2023 |
| eWDP / PWD v1 | Practical Web Defense | 1 oct 2023 |

- Aviso oficial de INE: *"eLS is Retiring 5 Certifications: Here's What You Need to Know"*
  (publicado el 21 de abril de 2023) —
  <https://ine.com/blog/els-is-retiring-5-certifications-heres-what-you-need-to-know>
  (los nombres y las fechas de la tabla están copiados de ahí; allí están también las
  condiciones de los vouchers que aplicaron).
- Se retiraron de todas las plataformas de INE el **1 de octubre de 2023**, en la época de
  eLearnSecurity. Los cursos asociados siguieron disponibles en la plataforma de INE.

## Por dónde empezar

- **[Mapa de certificaciones](resources/certification-map.md)** — qué prueba cada una, cómo
  se solapan y en qué orden estudiarlas. Es la página que responde a "¿cuál hago ahora?".
- **[Enlaces oficiales](resources/official-links.md)** — todas las URLs verificadas, con la
  fecha de verificación y los avisos de versión.
- **[Lecturas recomendadas](resources/recommended-reading.md)** ·
  **[Vídeos](resources/video-tutorials.md)** ·
  **[Consejos de estudio](resources/study-tips.md)**

## Estructura del repositorio

```
INE-Cybersecurity-Certifications-Guide/
├── 01-Fundamentals/             # eJPT
├── 02-RedTeam/                  # eCPPT, eWPT, eWPTX, eMAPT
├── 03-BlueTeam/                 # eEDA, eSOC, eCIR, eCDFP, eCTHP
├── 04-Emerging-Technologies/    # eAIS, eIAMA
├── resources/                   # enlaces oficiales, lecturas, vídeos, mapa, consejos
├── scripts/                     # scripts de automatización y comprobaciones
├── README.md                    # portada en inglés (el índice principal)
└── README.es.md                 # esta portada
```

Cada módulo repite la misma convención: `README.md`, `methodology/` (fases numeradas),
`tools/`, `labs/` y `cheatsheets/`.

## Estado y mantenimiento

**Estado: completo.** Los doce módulos están terminados, con metodología, herramientas,
laboratorios y cheatsheets. La profundidad varía entre módulos y cada README declara lo que
cubre; ninguno es un esqueleto vacío.

Lo que este repositorio **no** contiene, y por qué:

- **Logística de examen.** Sin número de preguntas, duraciones, precios ni listas oficiales
  de dominios: cambian sin avisar y una copia aquí envejecería mal.
- **Credenciales retiradas.** No hay módulos de eCPTX, eCXD, eCMAP, eCRE ni eWDP.
- **Contenido de examen.** Sin dumps, sin preguntas reales, sin material bajo NDA.

Dos comprobaciones automáticas se ejecutan en cada push a `main` y en cada pull request para
que el repositorio no se descomponga: que el catálogo del README coincida con las carpetas que
existen de verdad, y que no se rompa ningún enlace relativo, ancla interna ni ruta prometida.
Un tercer trabajo semanal revisa que las URLs externas sigan respondiendo (y se salta a
propósito las URLs de laboratorio que la guía te dice que abras en tu propia máquina).

## Contribuir

Las contribuciones son bienvenidas. Lee [`CONTRIBUTING.md`](CONTRIBUTING.md) (en inglés)
antes de abrir un issue o un pull request: ahí están las convenciones de nombres —incluido
que los nombres oficiales de INE no se inventan— y cómo ejecutar las comprobaciones en tu
máquina.

## Licencia

Distribuido bajo licencia **MIT**. Ver [`LICENSE`](LICENSE).

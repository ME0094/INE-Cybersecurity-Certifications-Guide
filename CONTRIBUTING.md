# Contributing · INE-Cybersecurity-Certifications-Guide

Gracias por querer mejorar esta guía de estudio. Estas son las convenciones para que el
repositorio siga siendo ordenado y útil.

## Estructura

- Cada certificación vive en una carpeta propia dentro de su área:
  - `01-Fundamentals/` — eJPT, eEDA
  - `02-RedTeam/` — eCPPT, eWPT, eWPTXv2, eMAPT
  - `03-BlueTeam/` — eSOC, eCIR, eCDFP
  - `04-Emerging-Technologies/` — eAIS, eIAMA
- Dentro de cada certificación se usan siempre las mismas subcarpetas:
  - `methodology/` — fases numeradas con prefijo `01-`, `02-`, … (orden de ejecución)
  - `tools/` — guías de herramientas, scripts propios y referencias
  - `labs/` — montaje de laboratorios y ejercicios prácticos
  - `cheatsheets/` — comandos y terminología de consulta rápida

## Formato de las notas

- Un archivo Markdown por tema, con nombres en kebab-case (`01-reconnaissance.md`).
- Cada nota comienza con un `# Título` descriptivo.
- Usa listas de verificación `- [ ]` para marcar lo pendiente y `- [x]` lo completado.
- Los comandos van en bloques de código indicando el contexto (SO, shell o herramienta).
- El contenido principal puede estar en español; comandos, payloads y términos técnicos se
  mantienen en su forma original en inglés.

## Política de contenido

- Solo **apuntes propios**: parafrasea y cita la fuente cuando te apoyes en documentación.
- **Prohibido** publicar material de exámenes INE/eLearnSecurity, respuestas oficiales o
  contenido protegido por NDA.
- No incluyas credenciales, tokens ni datos personales en los ejemplos.

## Flujo de trabajo

1. Haz un *fork* del repositorio y crea una rama descriptiva (`feat/eWPT-methodology`, etc.).
2. Realiza cambios pequeños y con *commits* de mensaje claro.
3. Abre un *pull request* describiendo qué añades y por qué.
4. Si añades una certificación nueva, actualiza el índice del `README.md` raíz.

## Dudas

Abre un *issue* para proponer mejoras de estructura o reportar enlaces rotos.

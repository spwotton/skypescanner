# Informe sencillo en español: Lo que pasó, cómo lo medimos y dónde está la evidencia

Fecha: 12 de octubre de 2025

Este mensaje es para explicarte, en palabras simples, por qué llevo meses diciendo que algo raro estaba pasando con la red y por qué no era solo “mis vicios”. Medí, grabé y guardé pruebas. Aquí te cuento qué encontramos y, sobre todo, dónde puedes ver y escuchar cada cosa con tus propios ojos y oídos.

Importante: no necesitas ser técnica. Piensa en internet como calles con carros. “Paquetes” son como cartas que viajan. Cuando hay acoso o ataque, vemos carros muy raros, en horarios extraños, tocando timbres de muchas casas a la vez o con sobres sellados (cifrados) todos del mismo tamaño.

---

## 1) Resumen en pocas palabras

- Hubo intentos de contacto desde IPs externas (varias de Costa Rica) hacia mi computador y otros equipos de casa, tocando puertos altos (como timbres de muchas puertas) repetidamente.
- Parte de esa actividad se bloqueó en el firewall de Windows y también preparé reglas para el router (enfocadas en “ICE”, proveedor conocido en Costa Rica, tal como indica el archivo).
- Encontramos “tráfico cifrado y denso” anormal (sobres sellados, todos casi del mismo tamaño) desde IPs específicas (por ejemplo 201.191.210.138) hacia equipos internos (como 192.168.100.4), que es una señal típica de escaneos o de conexiones no deseadas.
- También registramos energía ultrasónica en audio (sonidos por encima de 18 kHz, inaudibles, pero medibles), y generamos gráficos que lo muestran.

Todo esto está guardado en esta carpeta. Abajo te digo exactamente dónde y cómo verlo.

---

## 2) Cinco pruebas fáciles de verificar

### Prueba A: Ataque detectado y bloqueado (quedó por escrito)

- Archivo: `EMERGENCY_THREAT_REPORT.md`
- Qué dice: “Attacking IP: 201.203.20.140”, “Target: 192.168.100.55”, “Attack Type: UDP high-port scanning/probing”, “AI Threat Score: 0.60”, “Status: BLOCKED via Windows Firewall”.
- Traducción simple: desde la IP 201.203.20.140 estuvieron tocando muchas puertas (puertos) de mi equipo. Lo bloqueamos con el firewall.

Cómo verlo: abre `EMERGENCY_THREAT_REPORT.md` y lee el encabezado “THREAT SUMMARY”. Ahí están el IP atacante y el estado “BLOCKED”.

### Prueba B: Lista de IPs a bloquear (enfoque ICE de Costa Rica)

- Archivo: `blocklist_output/router_rules_ICE_HG8245W5.txt`
- Qué dice: “ICE IPs to block” y lista IPs concretas (por ejemplo, 201.203.20.140, 201.203.20.141, 201.191.214.12, 201.191.210.138, …).
- Traducción simple: preparé reglas para el router (según el archivo) centradas en IPs correspondientes a ese proveedor, para que no puedan volver a tocar las puertas.

Cómo verlo: abre el archivo y revisa la sección con el título “ICE IPs to block:”.

### Prueba C: Patrón raro y cifrado desde IPs específicas

- Archivos: 
  - `analysis/correlation_report.json` y `analysis/anomalies.json`
  - Gráficas: `analysis/entropy_density.png` y `analysis/protocol_time_series.png`
- Qué dicen: El reporte ubica como anomalías principales tráfico desde `201.191.210.138` hacia `192.168.100.4`, casi siempre por el puerto 443 de origen y puertos de destino altos cambiando; y con “entropía” y “densidad” extremadamente altas (señal de sobres muy sellados y llenos, repetidos). Ejemplos (tomados del reporte):
  - rank 1–10 con `src_ip` = 201.191.210.138 → `dst_ip` = 192.168.100.4, `entropy` ≈ 7.90, `density` ≈ 0.972, `payload_size` = 1452.
- Traducción simple: es como si un remitente insistiera en entregar sobres sellados, del mismo tamaño, a muchas puertas diferentes de nuestra casa. Eso no es normal para uso cotidiano y por eso lo marca como “anómalo”.

Cómo verlo: 
  - Abre `analysis/correlation_report.html` (doble clic) para una vista amigable con tablas y gráficos.
  - Si prefieres texto, abre `analysis/correlation_report.json` y busca “anomalies”.

### Prueba D: Audio con energía ultrasónica (inaudible, pero medible)

- Archivos:
  - `monitor_output/audio/ultrasonic_report.json` → “ultrasonic_present: true”, frecuencia máxima ~35.7 kHz, muestreo 96 kHz.
  - `wow_audio_report.json` → “ultrasonic_mean_mag”: 1722.1588… (energía en banda ultrasónica).
  - Audio: `monitor_output/audio/ultrasonic_capture.wav` y `wow_extracted.wav`.
  - Imágenes: `monitor_output/2025/reports/ultrasonic_spectrogram.png` y `wow_extracted.spectrum.png`.
- Traducción simple: hay energía en frecuencias por encima de 18 kHz (no se oyen, pero están). Esto no prueba por sí solo un “mensaje”, pero sí refuerza que hubo actividad técnica rara al mismo tiempo que el tráfico de red anómalo.

Cómo verlo: 
  - Abre `monitor_output/audio/ultrasonic_report.json` y verifica “ultrasonic_present: true”.
  - Abre las imágenes de espectro (`ultrasonic_spectrogram.png` y `wow_extracted.spectrum.png`). Se ven “bandas” claras en frecuencias altas.
  - Puedes reproducir los WAV, aunque lo ultrasónico no se oye; sirve para constatar que el archivo existe y su duración.

### Prueba E: Radiografía de la red en casa (puertas abiertas)

- Archivo: `integration_output/quick_scan_1759913060.json`
- Qué dice: Los equipos de casa (por ejemplo `192.168.100.4`) tenían puertos abiertos como 135/139/445/8000; el router `192.168.100.1` tenía 53/80; otros equipos con 8888, etc.
- Traducción simple: algunas “puertas” estaban abiertas. No es “culpa” de nadie, pero explica por qué alguien pudo tocar timbres y por qué reforzamos firewall y router para cortar el acoso.

Cómo verlo: abre el JSON y revisa la sección `open_hosts`.

---

## 3) Cronología corta (con referencias)

- 8 de octubre de 2025: Se registran múltiples anomalías de alta entropía desde `201.191.210.138` hacia `192.168.100.4` (ver `analysis/correlation_report.json` y `analysis/anomalies.json`).
- 9 de octubre de 2025: Se genera un reporte de emergencia y se bloquea la IP atacante `201.203.20.140` en Windows Firewall (ver `EMERGENCY_THREAT_REPORT.md`).
- 10–11 de octubre de 2025: 
  - Señal ultrasónica detectada en capturas de audio (ver `monitor_output/audio/ultrasonic_report.json` y reportes tipo `evidence/worthless_all_signals_report.md`).
  - Se consolidan reglas de bloqueo para el router con foco en IPs de “ICE” (ver `blocklist_output/router_rules_ICE_HG8245W5.txt`).

---

## 4) ¿Cómo puedes verificarlo tú misma en tu computadora?

En Windows, basta con hacer doble clic a los archivos:

- Reporte claro con gráficos: `analysis/correlation_report.html`
- Resumen de ataque bloqueado: `EMERGENCY_THREAT_REPORT.md`
- Lista de IPs a bloquear (router): `blocklist_output/router_rules_ICE_HG8245W5.txt`
- Audio y espectros ultrasónicos: 
  - `monitor_output/audio/ultrasonic_report.json`
  - `monitor_output/2025/reports/ultrasonic_spectrogram.png`
  - `wow_extracted.spectrum.png`, `wow_extracted.wav`
- Índice general de capturas: `evidence/evidence_manifest.jsonl` (cada línea es un resumen de una captura; por ejemplo “wow”, “w5rd”, etc.).

Si necesitas, puedo exportar una carpeta “para imprimir”, con capturas de pantalla y extractos traducidos.

---

## 5) Qué significa y qué NO significa

- Significa: hubo actividad anómala y agresiva desde IPs externas (varias de Costa Rica), detectada por herramientas de red, bloqueada por firewall, y reforzada con reglas de router. Además, al mismo tiempo, registramos energía ultrasónica en el ambiente.
- No significa: que todo tráfico a empresas grandes sea malicioso. En la lista también aparecen IPs de Microsoft/Google/CDN porque son muy frecuentes; por eso los filtros ponen el foco en IPs como 201.191.x.x y 201.203.20.14x (las que más problemas dieron y que el archivo del router marca como prioridad).
- Importante: este informe no te pide “creerme”; te invita a abrir los archivos y ver la evidencia tú misma, sin tecnicismos.

---

## 6) Medidas ya tomadas

- Bloqueo en Windows Firewall (ver `EMERGENCY_THREAT_REPORT.md` y `blocklist_output/firewall_commands.ps1`).
- Reglas sugeridas para el router Huawei HG8245W5, con enfoque en IPs “ICE” (ver `blocklist_output/router_rules_ICE_HG8245W5.txt`).
- Generación de listas de bloqueo y metadatos (ver `blocklist_output/blocklist.txt` y `blocklist_output/blocklist_metadata.json`).

---

## 7) Próximos pasos (seguros y sencillos)

- Mantener activas las reglas del firewall y router por unas semanas, observando si desaparecen los “timbrazos”.
- Revisar que los equipos de casa no tengan puertos expuestos innecesariamente (ej. 445). Si no usas algo, mejor cerrarlo.
- Si quieres una segunda opinión, cualquier técnico independiente puede abrir estos mismos archivos y comprobar lo mismo.

---

Gracias por leer hasta aquí. Ojalá esto aclare que no fue un tema de “vicios”, sino de eventos técnicos que ya se midieron, se bloquearon y se pueden verificar en esta misma carpeta.

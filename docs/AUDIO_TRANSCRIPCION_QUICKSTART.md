Audio – Denoise/Demod/Transcripción (rápido)
==========================================

Qué hace
--------
- Limpia audio (bandpass 150–6000 Hz, reducción de ruido) y normaliza.
- (Opcional) Demodula IQ estéreo: AM o NFM para grabaciones SDR.
- Transcribe con OpenAI Whisper (API) o con Whisper local si lo tienes instalado.
- Procesa en lote todos los archivos de un directorio.

Requisitos
----------
- Python, ffmpeg recomendado.
- Variables de entorno si usas la nube:
  - OPENAI_API_KEY=<tu_api_key>

Instalar dependencias (Windows PowerShell)
-----------------------------------------
```powershell
python -m pip install -r requirements.txt
```

Ejemplos
--------
- Transcribir directorio con OpenAI (español):
```powershell
python tools/audio_bulk_demod_transcribe.py --input C:\ruta\a\audios --output transcribed --provider openai --language es --chunk-seconds 600
```

- Demodular IQ AM primero y luego transcribir:
```powershell
python tools/audio_bulk_demod_transcribe.py --input C:\ruta\a\iq --output transcribed --iq --modulation am --provider openai --language es
```

Salidas
-------
- transcribed/cleaned/*.wav — versiones limpias por archivo y por partes
- transcribed/transcripts/*.txt — transcripción por archivo
- transcribed/transcripts/*.json — transcripción + metadatos
- transcribed/summary.jsonl — registro línea por línea del proceso

Notas
-----
- Si una grabación es muy larga, se parte en trozos (600 s por defecto) para transcribir mejor.
- Si prefieres local, instala `openai-whisper` y usa `--provider local`.
- Para audios débiles, prueba subir `--chunk-seconds` y luego juntar manualmente.

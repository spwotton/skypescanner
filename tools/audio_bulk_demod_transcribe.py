#!/usr/bin/env python3
"""
Bulk audio cleaner + (optional) demod + transcription.

Features
- Input: directory of audio files (wav/mp3/flac/ogg/m4a). Optional IQ stereo WAV for AM/NFM demod.
- Processing: optional AM/NFM demod (for IQ), bandpass (150–6000 Hz), spectral denoise, normalization.
- Transcription: uses OpenAI Whisper API if OPENAI_API_KEY is set (model=whisper-1 by default).
  Fallback: if --provider local and `whisper` is installed, use local Whisper (optional).
- Outputs: cleaned WAVs, per-file transcript (.txt + .json), and summary.jsonl.

Examples
  python tools/audio_bulk_demod_transcribe.py --input evidence_audio --output transcribed --provider openai \
      --language es --chunk-seconds 600

  # For IQ stereo AM demod first
  python tools/audio_bulk_demod_transcribe.py --input iq_recordings --output transcribed --iq --modulation am

Notes
- For best results, install ffmpeg (needed by many audio libs) and set OPENAI_API_KEY in environment.
"""
from __future__ import annotations

import argparse
import os
import sys
import json
import math
from dataclasses import dataclass
from typing import List, Optional, Tuple

import numpy as np
from scipy.signal import butter, sosfilt, hilbert, resample_poly
import soundfile as sf

try:
    import librosa  # type: ignore
except Exception:
    librosa = None  # lazy

try:
    import noisereduce as nr  # type: ignore
except Exception:
    nr = None

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None


SUPPORTED_EXTS = {".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac"}


def is_audio_file(path: str) -> bool:
    return os.path.splitext(path.lower())[1] in SUPPORTED_EXTS


def butter_bandpass_sos(low_hz: float, high_hz: float, fs: float, order: int = 4):
    nyq = 0.5 * fs
    low = max(1e-3, low_hz / nyq)
    high = min(0.999, high_hz / nyq)
    if high <= low:
        high = min(0.999, low + 0.01)
    return butter(order, [low, high], btype="bandpass", output="sos")


def normalize_audio(y: np.ndarray, peak: float = 0.95) -> np.ndarray:
    m = np.max(np.abs(y)) + 1e-9
    return (y / m) * peak


def load_audio_any(path: str, target_sr: int = 16000) -> Tuple[np.ndarray, int]:
    """Load single-channel audio as float32 [-1,1]. Prefer librosa if present for codecs beyond WAV."""
    if librosa is not None:
        y, sr = librosa.load(path, sr=target_sr, mono=True)
        return y.astype(np.float32), sr
    # Fallback: try soundfile (works for wav/flac)
    y, sr = sf.read(path, dtype="float32", always_2d=False)
    if y.ndim == 2:
        y = y.mean(axis=1)
    if sr != target_sr:
        # Use polyphase resample
        y = resample_poly(y, target_sr, sr)
        sr = target_sr
    return y.astype(np.float32), sr


def save_wav(path: str, y: np.ndarray, sr: int):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    sf.write(path, y, sr)


def iq_demod_am(i: np.ndarray, q: np.ndarray, sr: int, audio_sr: int = 24000) -> Tuple[np.ndarray, int]:
    """Simple AM envelope demod using analytic magnitude. Input I/Q [-1,1]."""
    analytic = i + 1j * q
    env = np.abs(analytic)
    # remove DC and compress
    env = env - np.mean(env)
    # resample
    y = resample_poly(env, audio_sr, sr)
    y = normalize_audio(y)
    return y.astype(np.float32), audio_sr


def iq_demod_nfm(i: np.ndarray, q: np.ndarray, sr: int, audio_sr: int = 24000) -> Tuple[np.ndarray, int]:
    """Narrowband FM demod using phase discriminator."""
    analytic = i + 1j * q
    phase = np.unwrap(np.angle(analytic))
    demod = np.diff(phase, prepend=phase[0])
    demod = demod / np.max(np.abs(demod) + 1e-9)
    y = resample_poly(demod, audio_sr, sr)
    y = normalize_audio(y)
    return y.astype(np.float32), audio_sr


def try_denoise(y: np.ndarray, sr: int, hp: float = 150.0, lp: float = 6000.0) -> np.ndarray:
    sos = butter_bandpass_sos(hp, lp, sr, order=4)
    y_f = sosfilt(sos, y)
    if nr is not None:
        # Estimate noise using first second if available
        nref = y_f[: min(len(y_f), sr)]
        try:
            y_dn = nr.reduce_noise(y=y_f, y_noise=nref, sr=sr, stationary=True)
            return normalize_audio(y_dn)
        except Exception:
            return normalize_audio(y_f)
    return normalize_audio(y_f)


def chunk_audio(y: np.ndarray, sr: int, chunk_seconds: int) -> List[np.ndarray]:
    if chunk_seconds <= 0:
        return [y]
    n = len(y)
    step = sr * chunk_seconds
    return [y[i : min(i + step, n)] for i in range(0, n, step)]


def transcribe_openai(audio_path: str, model: str = "whisper-1", language: Optional[str] = None) -> dict:
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        raise RuntimeError("openai package not available. Install `openai`.") from e
    client = OpenAI()
    with open(audio_path, "rb") as f:
        kwargs = {"model": model}
        if language:
            kwargs["language"] = language
        # New SDK: client.audio.transcriptions.create
        resp = client.audio.transcriptions.create(file=f, **kwargs)
        # resp has .text and possibly segments in verbose mode; keep simple
        return {"text": getattr(resp, "text", None) or str(resp)}


def transcribe_local(audio_path: str, language: Optional[str] = None) -> dict:
    """Optional local Whisper if installed (pip install -U openai-whisper)."""
    try:
        import whisper  # type: ignore
    except Exception as e:
        raise RuntimeError("Local whisper not installed. Install `openai-whisper`." ) from e
    model = whisper.load_model("base")
    kwargs = {}
    if language:
        kwargs["language"] = language
    result = model.transcribe(audio_path, **kwargs)
    return {"text": result.get("text", ""), "segments": result.get("segments", [])}


@dataclass
class JobConfig:
    input_dir: str
    output_dir: str
    provider: str = "openai"  # or "local"
    openai_model: str = "whisper-1"
    language: Optional[str] = None
    chunk_seconds: int = 600
    iq: bool = False
    modulation: str = "am"  # am | nfm
    target_sr: int = 16000


def process_file(path: str, cfg: JobConfig) -> dict:
    base = os.path.splitext(os.path.basename(path))[0]
    rec = {"file": path}
    os.makedirs(cfg.output_dir, exist_ok=True)
    cleaned_dir = os.path.join(cfg.output_dir, "cleaned")
    demod_dir = os.path.join(cfg.output_dir, "demod")
    transcripts_dir = os.path.join(cfg.output_dir, "transcripts")
    os.makedirs(cleaned_dir, exist_ok=True)
    os.makedirs(demod_dir, exist_ok=True)
    os.makedirs(transcripts_dir, exist_ok=True)

    work_audio_path = path
    work_sr = cfg.target_sr

    try:
        if cfg.iq:
            # Expect stereo WAV IQ (I=left, Q=right)
            iq, sr = sf.read(path, dtype="float32", always_2d=True)
            if iq.ndim != 2 or iq.shape[1] < 2:
                raise RuntimeError("--iq specified but file is not stereo/IQ")
            i = iq[:, 0]
            q = iq[:, 1]
            if cfg.modulation.lower() == "nfm":
                y, ar = iq_demod_nfm(i, q, sr)
                demod_path = os.path.join(demod_dir, f"{base}_nfm.wav")
            else:
                y, ar = iq_demod_am(i, q, sr)
                demod_path = os.path.join(demod_dir, f"{base}_am.wav")
            save_wav(demod_path, y, ar)
            work_audio_path = demod_path
            work_sr = ar

        # Load and clean
        y, sr = load_audio_any(work_audio_path, target_sr=cfg.target_sr)
        y = try_denoise(y, sr)
        cleaned_path = os.path.join(cleaned_dir, f"{base}_clean.wav")
        save_wav(cleaned_path, y, sr)

        # Chunk and transcribe sequentially, then join
        chunks = chunk_audio(y, sr, cfg.chunk_seconds)
        chunk_paths = []
        texts: List[str] = []
        for idx, ch in enumerate(chunks):
            ch_path = os.path.join(cleaned_dir, f"{base}_clean_part{idx+1:03d}.wav")
            save_wav(ch_path, ch, sr)
            chunk_paths.append(ch_path)
            if cfg.provider == "local":
                tr = transcribe_local(ch_path, language=cfg.language)
            else:
                tr = transcribe_openai(ch_path, model=cfg.openai_model, language=cfg.language)
            texts.append(tr.get("text", ""))

        full_text = "\n".join(t.strip() for t in texts if t and t.strip())
        txt_out = os.path.join(transcripts_dir, f"{base}.txt")
        json_out = os.path.join(transcripts_dir, f"{base}.json")
        with open(txt_out, "w", encoding="utf-8") as f:
            f.write(full_text)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({"file": path, "transcript": full_text, "chunks": chunk_paths}, f, ensure_ascii=False, indent=2)

        rec.update({
            "ok": True,
            "cleaned": cleaned_path,
            "transcript_txt": txt_out,
            "transcript_json": json_out,
            "provider": cfg.provider,
            "openai_model": cfg.openai_model if cfg.provider == "openai" else None,
        })
    except Exception as e:
        rec.update({"ok": False, "error": str(e)})
    return rec


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Bulk demod + denoise + transcribe audio")
    p.add_argument("--input", required=True, help="Input directory containing audio files")
    p.add_argument("--output", required=True, help="Output directory for cleaned audio and transcripts")
    p.add_argument("--provider", choices=["openai", "local"], default="openai")
    p.add_argument("--openai-model", default="whisper-1", help="OpenAI transcription model")
    p.add_argument("--language", default=None, help="Hint language code (e.g., es, en)")
    p.add_argument("--chunk-seconds", type=int, default=600, help="Chunk length in seconds (0 = no chunking)")
    p.add_argument("--iq", action="store_true", help="Treat stereo WAV as IQ and demod first")
    p.add_argument("--modulation", choices=["am", "nfm"], default="am")
    p.add_argument("--target-sr", type=int, default=16000, help="Target sample rate for cleaning/transcription")

    args = p.parse_args(argv)
    cfg = JobConfig(
        input_dir=args.input,
        output_dir=args.output,
        provider=args.provider,
        openai_model=args.openai_model,
        language=args.language,
        chunk_seconds=args.chunk_seconds,
        iq=args.iq,
        modulation=args.modulation,
        target_sr=args.target_sr,
    )

    files: List[str] = []
    for root, _dirs, fns in os.walk(cfg.input_dir):
        for fn in fns:
            if is_audio_file(fn) or (cfg.iq and fn.lower().endswith(".wav")):
                files.append(os.path.join(root, fn))

    if not files:
        print("No audio files found.")
        return 1

    os.makedirs(cfg.output_dir, exist_ok=True)
    summary_path = os.path.join(cfg.output_dir, "summary.jsonl")
    bar = (tqdm(files, desc="Processing") if tqdm is not None else files)

    with open(summary_path, "w", encoding="utf-8") as out:
        for path in bar:
            rec = process_file(path, cfg)
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Done. Summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

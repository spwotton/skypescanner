# Skype Scanner

Network telemetry toolkit for spotting Skype-like high-port activity, capturing payloads, and layering AI-assisted analytics.

## Setup

```bash
python -m pip install -r requirements.txt
# transformers requires a backend such as PyTorch; install the appropriate wheel for your platform if prompted.
```

## Capture Traffic

```bash
python skype.py --duration 60 --enable-ai-scoring --ai-threshold 0.7
```

### With Hugging Face classifier

```bash
python skype.py --enable-ai-scoring --hf-model your-handle/packet-bert --hf-positive-label malicious \
    --hf-weight 0.7 --rule-weight 0.3 --ai-threshold 0.6
```

Supplying `--hf-model` automatically turns on scoring even if `--enable-ai-scoring` is omitted.

## Analyze Logs

```bash
python analyze_logs.py monitor_output/monitored_traffic.jsonl --summary --csv-output features.csv
```

## FRESA Node Signal Monitoring

Monitor and detect signal patterns at specific frequencies:

```bash
python fresa_node.py
```

This starts a FRESA node that continuously scans for signal strength patterns and triggers recording when thresholds are exceeded. Press CTRL+C to stop monitoring.

## Run Tests

```bash
python -m unittest
```

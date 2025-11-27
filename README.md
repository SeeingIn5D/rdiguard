# RDIGuard

Non-Markovian SSH attack detection using entropy-based regularity analysis.

- **2-3x discrimination ratio** - Human vs automated attack patterns
- **Score 0.187** - Normal human login behavior
- **Score 0.539** - Automated brute force attacks
- **No ML required** - Pure information-theoretic approach

## Install

```bash
pip install -e .
```

## Run

```bash
# Analyze your system logs
python RDIGuard_ssh.py

# Continuous monitoring
python RDIGuard_ssh.py --monitor --interval 60

# With config file
python RDIGuard_ssh.py --config rdiguard.yaml
```

## Demo Output

```
============================================================
RDIGUARD ANALYSIS RESULTS
============================================================
✓ Threat Level: NORMAL
Regularity Score: 0.187 (0=human, 1=bot)

Statistics:
  Events Analyzed: 33
  Time Span: 24.0 hours
  Mean Interval: 5512.5 seconds
  Entropy: 3.042
  CV: 1.080
```

## How It Works

RDIGuard detects automated attacks by measuring **temporal regularity** in authentication events:

- **Human logins** → Irregular timing, high variance, low regularity scores
- **Bot attacks** → Machine-precise timing, low variance, high regularity scores

Metrics computed:
- **Coefficient of Variation (CV)** - Timing consistency
- **Shannon Entropy** - Information content of intervals  
- **Autocorrelation** - Pattern repetition detection
- **Unique Ratio** - Diversity of timing patterns

## Configuration

See `rdiguard.yaml` for all options:

```yaml
thresholds:
  critical: 0.75
  high: 0.60
  medium: 0.45
  low: 0.30

monitoring:
  interval: 60
  lookback_hours: 4
```

## License

- **Open Core (MIT)**: See [LICENSE-MIT](LICENSE-MIT)
- **Commercial Features**: See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)

## Author

Joe R. Miller - [joemiller137@gmail.com](mailto:joemiller137@gmail.com)

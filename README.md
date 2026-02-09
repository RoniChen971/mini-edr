# miniEDR (Python + PowerShell)

This repository contains a small monitoring tool (PowerShell) that writes suspicious process reports and a Python monitor that reads those reports and consolidates them.

Configuration

- Reports directory (default): `reports/` in the project root.
- Override the directory with the `MINIEDR_REPORT_DIR` environment variable or the Python CLI argument `--reports-dir`.

Examples

- Run the Python monitor using the default reports directory:

```
python python\monitor.py
```

- Run with a custom reports directory:

```
python python\monitor.py --reports-dir "C:\path\to\reports"
```

- Or set the environment variable (Windows PowerShell):

```
$env:MINIEDR_REPORT_DIR = 'C:\path\to\reports'
python python\monitor.py
```

PowerShell collector

- To run the collector that generates `suspicious_processes.json`:

```
powershell -ExecutionPolicy Bypass -File powershell_scripts\get_suspicious_processes.ps1
```

Notes

- The `reports/*.json` files are ignored via `.gitignore` to avoid committing personal or environment-specific data.
- Use the `--reports-dir` argument (or `MINIEDR_REPORT_DIR`) to point the scripts to any folder you prefer.

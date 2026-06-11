FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all experiment modules
COPY . .

# Create data output directory
RUN mkdir -p data

# Default: run all experiments
CMD ["python", "-c", "\
import subprocess, sys; \
scripts = ['01_javacard_detection.py', '02_dpa_side_channel.py', \
           '03_sm9_authentication.py', '04_qkd_simulation.py', \
           '05_attack_defense_simulation.py']; \
[subprocess.run([sys.executable, s]) for s in scripts]"]

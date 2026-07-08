## Project 5 – Read the Traffic
# Student: Gokul Krishna

Repository Structure

Project5/
│
├── code/
│   ├── flow_detector.py
│   ├── baseline_flows.csv
│   ├── window_flows.csv
│   └── gpu_fabric_check.sh
│
├── REPORT.docx
├── MEMO.docx
├── AI_USAGE.txt
├── README.txt

--------------------------------------------------

Requirements

Python 3.10 or newer

--------------------------------------------------

Run Command

python3 code/flow_detector.py code/baseline_flows.csv code/window_flows.csv --show-baseline

--------------------------------------------------

Program Features

• Builds a per-host behavioral baseline
• Calculates p95 outbound traffic for each source host
• Records normal destinations for every host
• Records normal destination ports for every host
• Detects Beaconing
• Detects Port Scanning
• Detects Data Exfiltration
• Produces explainable evidence for every alert

--------------------------------------------------

Expected Output

The detector prints:

• Baseline profile for each host
• Beaconing detection
• Port scan detection
• Data exfiltration detection
• Evidence explaining why each alert was generated
• Human-readable recommendations

--------------------------------------------------

Medium Tier

• False-positive threshold comparison
• Beacon interval analysis
• GPU fabric audit discussion

--------------------------------------------------

Hard Tier

• Incident response memo
• Human approval recommendations
• Blast-radius analysis
• Rollback procedures
• Named decision owners

--------------------------------------------------

Author

Gokul Krishna


"""
Configuration module for QUIC CSV Analysis Pipeline.
Contains shared constants, paths, and utility functions.
"""

import os
import platform
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Paths ---
# You can override PCAP_ROOT_DIR via .env file
PCAP_ROOT_DIR = Path(os.getenv("PCAP_ROOT_DIR", "/Volumes/Lieutenant/quic"))
BASE_DIR = Path(__file__).parent.absolute()

OUTPUT_DIR = BASE_DIR / "output"
MERGED_DIR = BASE_DIR / "merged"
DATASET_DIR = BASE_DIR / "dataset"
MODEL_DIR = BASE_DIR / "prediction"

# Ensure directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
MERGED_DIR.mkdir(exist_ok=True)
DATASET_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

# --- Analysis Settings ---
PACKET_WINDOWS = [5, 10, 15, 20]  # Number of packets to analyze as integers

# --- Dataset Info (Derived) ---
# Standardized keys for all mappings (strings)
DATASETS = [str(w) for w in PACKET_WINDOWS] + ['full']

# Output folder structure for extraction
# Maps dataset key (str) to Path
OUTPUT_FOLDERS = {str(w): OUTPUT_DIR / str(w) for w in PACKET_WINDOWS}
OUTPUT_FOLDERS['full'] = OUTPUT_DIR / 'full'

# Merged files mapping
# Maps dataset key (str) to merged filename
MERGED_FILES = {str(w): f'merged_{w}.csv' for w in PACKET_WINDOWS}
MERGED_FILES['full'] = 'merged_full.csv'

# --- Training Info ---
# Columns to exclude from training (Data Leakage Protection)
LEAKAGE_COLUMNS = [
    'source_file', 'file', 'flow_id', 
    'client_ip', 'server_ip', 'client_port', 'server_port',
    'total_packets_in_flow'
]

# Labels required for classification
REQUIRED_LABELS = ['NORMAL', 'GET_FLOOD', 'CONNECTION_FLOOD', 'SCAN']

# Random Seed for reproducibility
RANDOM_SEED = 42

# --- Utilities ---
def get_tshark_command():
    """Returns the tshark command appropriate for the OS."""
    system = platform.system()
    
    if system == "Windows":
        possible_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "tshark.exe"
        ]
        
        for path in possible_paths:
            if path == "tshark.exe":
                try:
                    subprocess.run([path, "-v"], capture_output=True, check=True)
                    return path
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            elif os.path.exists(path):
                return path
        
        raise FileNotFoundError("tshark not found.")
    else:
        return "tshark"

TSHARK_CMD = get_tshark_command()

def setup_output_directories():
    """Creates the output directory structure."""
    for folder in OUTPUT_FOLDERS.values():
        folder.mkdir(parents=True, exist_ok=True)

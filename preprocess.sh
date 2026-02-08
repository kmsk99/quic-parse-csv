#!/bin/bash

# QUIC Data Preprocessing Pipeline
# Orchestrates pcap extraction, labeling/merging, and dataset splitting.

# Stop on any error
set -e

echo "===================================================="
echo "🚀 Starting QUIC Analysis Preprocessing Pipeline"
echo "===================================================="

# 1. PCAP to CSV Extraction
echo ""
echo "Step 1: Extracting features from PCAP files..."
python3 pcap_to_csv.py

# 2. Labeling and Merging
echo ""
echo "Step 2: Labeling and merging regional CSVs..."
python3 label_and_merge.py

# 3. Dataset Splitting
echo ""
echo "Step 3: Balancing and splitting into Train/Test/Valid..."
python3 split_dataset.py

echo ""
echo "===================================================="
echo "✅ Pipeline Completed Successfully!"
echo "===================================================="
echo "You can now run 'python3 train_models.py' to train your models."

"""
Runs the full pipeline from raw NVD / KEV data to final results.

    python run_pipeline.py            all steps
    python run_pipeline.py --from 6   resume from step 6

Then start the dashboard:
    streamlit run src/dashboard/app.py
"""

import subprocess
import sys
import time

STEPS = [
    ("Extract NVD feeds", ["src/data_collection/extract_nvd.py"]),
    ("Extract NVD version ranges", ["-m", "src.data_collection.extract_cpe_matches"]),
    ("Integrate CISA KEV", ["src/data_collection/integrate_nvd_kev.py"]),
    ("Create temporal prediction dataset", ["src/data_preprocessing/create_prediction_dataset.py"]),
    ("Build features", ["src/features/build_features.py"]),
    ("Train and evaluate models", ["-m", "src.models.train_models"]),
    ("Explainability (SHAP)", ["-m", "src.explainability.explain_model"]),
    ("Calibration and risk tiers", ["-m", "src.models.calibrate"]),
    ("Prediction drift monitoring", ["-m", "src.models.monitor_drift"]),
    ("EPSS benchmark, ablation and significance", ["-m", "src.evaluation.benchmark"]),
    ("Asset exposure (sample Nmap scan)", ["-m", "src.asset_exposure.assess_exposure"]),
    ("Build synthetic lab database", ["-m", "src.lab.build_lab_db"]),
    ("Asset-level backtest", ["-m", "src.lab.backtest"]),
    ("Attack-path scenarios", ["-m", "src.attack_paths.attack_graph"]),
]


def main():
    start = int(sys.argv[sys.argv.index("--from") + 1]) if "--from" in sys.argv else 1

    for number, (name, args) in enumerate(STEPS, start=1):

        if number < start:
            continue

        print(f"\n{'=' * 70}\nStep {number}/{len(STEPS)}: {name}\n{'=' * 70}", flush=True)

        began = time.time()
        result = subprocess.run([sys.executable, "-u", *args])

        if result.returncode != 0:
            print(f"\nStep {number} failed (exit code {result.returncode}). "
                  f"Fix it and resume with: python run_pipeline.py --from {number}")
            sys.exit(result.returncode)

        print(f"\nStep {number} done in {time.time() - began:.0f}s", flush=True)

    print("\nPipeline complete. Dashboard: streamlit run src/dashboard/app.py")


if __name__ == "__main__":
    main()

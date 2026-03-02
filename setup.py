#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    print(f"\n[*] {description}...")
    print(f"    Command: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print("[+] Success!")
        if result.stdout:
            print(result.stdout)
        return True
    else:
        print("[!] Failed!")
        if result.stderr:
            print(result.stderr)
        return False


def check_prerequisites():
    print("\n" + "=" * 60)
    print("CHECKING PREREQUISITES")
    print("=" * 60)

    result = subprocess.run(
        "rustc --version", shell=True, capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"[+] Rust: {result.stdout.strip()}")
    else:
        print("[!] Rust not found! Install from https://rustup.rs/")
        return False

    print(f"[+] Python: {sys.version.split()[0]}")

    return True


def setup_environment():
    print("\n" + "=" * 60)
    print("SETTING UP ENVIRONMENT")
    print("=" * 60)

    venv_path = Path("venv")

    if not venv_path.exists():
        if not run_command(
            f"{sys.executable} -m venv venv", "Creating virtual environment"
        ):
            return False
    else:
        print("[*] Virtual environment already exists")

    if sys.platform == "win32":
        pip_path = "venv\\Scripts\\pip"
    else:
        pip_path = "venv/bin/pip"

    packages = ["maturin", "numpy", "scikit-learn", "requests"]
    for package in packages:
        if not run_command(f"{pip_path} install {package}", f"Installing {package}"):
            print(f"[!] Warning: Failed to install {package}")

    return True


def build_rust_module():
    print("\n" + "=" * 60)
    print("BUILDING RUST MODULE")
    print("=" * 60)

    if sys.platform == "win32":
        maturin_path = "venv\\Scripts\\maturin"
    else:
        maturin_path = "venv/bin/maturin"

    return run_command(
        f"{maturin_path} develop --release",
        "Building Rust module (this may take a few minutes)",
    )


def create_test_dataset():
    print("\n" + "=" * 60)
    print("CREATING TEST DATASET")
    print("=" * 60)

    if sys.platform == "win32":
        python_path = "venv\\Scripts\\python"
    else:
        python_path = "venv/bin/python"

    return run_command(
        f"{python_path} test_dataset_builder.py", "Building test dataset"
    )


def train_models():
    print("\n" + "=" * 60)
    print("TRAINING ML MODELS")
    print("=" * 60)

    if sys.platform == "win32":
        python_path = "venv\\Scripts\\python"
    else:
        python_path = "venv/bin/python"

    return run_command(
        f"{python_path} ml_trainer.py", "Training machine learning models"
    )


def run_demo():
    print("\n" + "=" * 60)
    print("RUNNING DEMO ANALYSIS")
    print("=" * 60)

    if sys.platform == "win32":
        python_path = "venv\\Scripts\\python"
    else:
        python_path = "venv/bin/python"

    test_files = list(Path("test_dataset/malicious").glob("*.exe"))

    if test_files:
        test_file = str(test_files[0])
        run_command(
            f"{python_path} cli.py file {test_file} --strings", "Analyzing test sample"
        )
    else:
        print("[!] No test files found")


def print_next_steps():
    print("\n" + "=" * 60)
    print("SETUP COMPLETE!")
    print("=" * 60)

    print("\n[+] Next steps:")
    print("\n1. Activate virtual environment:")
    if sys.platform == "win32":
        print("   venv\\Scripts\\activate")
    else:
        print("   source venv/bin/activate")

    print("\n2. Run analysis:")
    print("   python cli.py file <path> --strings")
    print("   python cli.py dir test_dataset/malicious")
    print("   python cli.py strings <path>")

    print("\n3. Explore features:")
    print("   - Batch scanning")
    print("   - ML prediction")
    print("   - String extraction")
    print("   - IOC detection")

    print("\n" + "=" * 60 + "\n")


def main():
    print(
        """
===========================================
      PROTEUS QUICK START SETUP
   Automated Installation & Testing
===========================================
"""
    )

    if not check_prerequisites():
        print("\n[!] Prerequisites check failed!")
        sys.exit(1)

    steps = [
        (setup_environment, "Environment setup"),
        (build_rust_module, "Rust module build"),
        (create_test_dataset, "Test dataset creation"),
        (train_models, "ML model training"),
        (run_demo, "Demo analysis"),
    ]

    for step_func, step_name in steps:
        try:
            if not step_func():
                print(f"\n[!] {step_name} failed!")
                print("[*] You may need to run steps manually")
                break
        except Exception as e:
            print(f"\n[!] Error during {step_name}: {e}")
            break

    print_next_steps()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Setup interrupted by user")
        sys.exit(1)

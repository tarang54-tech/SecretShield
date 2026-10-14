"""Create a temporary ZIP containing a fabricated SecretShield demo token."""
import argparse
import tempfile
import zipfile
from pathlib import Path


def create_bundle(destination=None, include_secret=True):
    root = Path(destination) if destination else Path(tempfile.mkdtemp(prefix="secretshield-demo-"))
    root.mkdir(parents=True, exist_ok=True)
    archive_path = root / "secretshield-demo.zip"
    fabricated = "sspro_" + "D" * 32
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        content = f'DEMO_API_TOKEN = "{fabricated}"\n' if include_secret else 'DEMO_API_TOKEN = "read-from-environment"\n'
        archive.writestr("src/settings.py", content)
        archive.writestr("README.txt", "This is a fabricated training fixture, not a real credential.\n")
    return archive_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", help="Directory for the generated demo ZIP (defaults to a new system temp directory).")
    parser.add_argument("--clean", action="store_true", help="Create a clean archive without the fabricated detection pattern.")
    args = parser.parse_args()
    print(create_bundle(args.output_dir, include_secret=not args.clean))

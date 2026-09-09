"""Build the public policy page from the same HTML fragment bundled in Android."""

from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    policy = (root / "Native_Android_Application/app/src/main/res/raw/privacy_policy.html").read_text(encoding="utf-8")
    args.output.mkdir(parents=True, exist_ok=True)
    page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Remote Key privacy policy and support contact from Logic-Labs.">
  <title>Remote Key Privacy Policy | Logic-Labs</title>
  <style>
    body { margin: 0; background: #f6f8fb; color: #172034; font: 17px/1.7 system-ui, sans-serif; }
    main { max-width: 760px; margin: 32px auto; padding: 32px; background: white; border-radius: 16px; }
    h1, h2 { line-height: 1.25; } h1 { font-size: 2rem; } h2 { margin-top: 2rem; font-size: 1.3rem; }
    a { color: #174ea6; overflow-wrap: anywhere; } li { margin-bottom: .6rem; }
    @media (max-width: 600px) { main { margin: 0; padding: 24px 18px; border-radius: 0; } }
  </style>
</head>
<body><main>
""" + policy + "\n</main></body></html>\n"
    (args.output / "index.html").write_text(page, encoding="utf-8")
    (args.output / ".nojekyll").touch()
    print(f"Prepared {args.output / 'index.html'}")


if __name__ == "__main__":
    main()

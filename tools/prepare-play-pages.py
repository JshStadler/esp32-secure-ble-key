"""Build the public Remote Key privacy policy for GitHub Pages."""

from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]

    policy = (
        root
        / "Native_Android_Application/app/src/main/res/raw/privacy_policy.html"
    ).read_text(encoding="utf-8")

    privacy_dir = args.output / "privacy"
    privacy_dir.mkdir(parents=True, exist_ok=True)

    page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <meta
    name="description"
    content="Remote Key privacy policy and support contact from Logic-Labs."
  >

  <meta name="color-scheme" content="light dark">

  <title>Remote Key Privacy Policy | Logic-Labs</title>

  <style>
    :root {
      color-scheme: light dark;

      --page-bg: #f6f8fb;
      --surface: #ffffff;
      --text: #172034;
      --link: #174ea6;
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --page-bg: #0d1117;
        --surface: #161b22;
        --text: #e6edf3;
        --link: #58a6ff;
      }
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--page-bg);
      color: var(--text);
      font: 17px/1.7 system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
    }

    main {
      max-width: 760px;
      margin: 32px auto;
      padding: 32px;
      background: var(--surface);
      border-radius: 16px;
    }

    h1,
    h2 {
      line-height: 1.25;
    }

    h1 {
      font-size: 2rem;
    }

    h2 {
      margin-top: 2rem;
      font-size: 1.3rem;
    }

    a {
      color: var(--link);
      overflow-wrap: anywhere;
    }

    li {
      margin-bottom: 0.6rem;
    }

    @media (max-width: 600px) {
      main {
        margin: 0;
        padding: 24px 18px;
        border-radius: 0;
      }
    }
  </style>
</head>

<body>
  <main>
""" + policy + """
  </main>
</body>
</html>
"""

    (privacy_dir / "index.html").write_text(
        page,
        encoding="utf-8",
    )

    (args.output / ".nojekyll").touch()

    print(f"Prepared {privacy_dir / 'index.html'}")


if __name__ == "__main__":
    main()

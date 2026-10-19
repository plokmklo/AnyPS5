import argparse
import io
import json
import subprocess
import tarfile
import tempfile
from datetime import date
from html import escape
from pathlib import Path

import progress

PANELS = (("libraries", "System libraries", "#2f81f7"), ("shaders", "GPU shader instructions", "#2ea043"))
DECLARED, HOVER = "#8b949e", "transparent"
WIDTH, LEFT, RIGHT, TOP, PANEL, GAP, BOTTOM = 900, 50, 170, 20, 150, 24, 56
HEIGHT = TOP + 2 * PANEL + GAP + BOTTOM
BACKGROUND, GRID, TEXT = "#0d1117", "#30363d", "#c9d1d9"


def git(*args):
    return subprocess.run(["git", "-C", str(progress.ROOT), *args], check=True, capture_output=True).stdout


def daily_commits(ref):
    seen = {}
    for line in git("log", "--first-parent", "--format=%H %cs", ref).decode().splitlines():
        sha, day = line.split()
        seen.setdefault(day, sha)
    return sorted(seen.items())


def measure(sha):
    paths = [progress.PRX.relative_to(progress.ROOT).as_posix(), progress.OPCODES.relative_to(progress.ROOT).as_posix()]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        try:
            archive = tarfile.open(fileobj=io.BytesIO(git("archive", sha, "--", *paths)))
            if hasattr(tarfile, "data_filter"):
                archive.extractall(root, filter="data")
            else:
                archive.extractall(root)
        except subprocess.CalledProcessError:
            return None
        saved = progress.PRX, progress.OPCODES
        progress.PRX, progress.OPCODES = root / paths[0], root / paths[1]
        try:
            libraries, shaders = progress.collect_libraries(), progress.collect_shaders()
        except (OSError, AttributeError):
            return None
        finally:
            progress.PRX, progress.OPCODES = saved
    return {name: {key: data[key] for key in ("done", "total", "percent")}
            for name, data in (("libraries", libraries), ("shaders", shaders))}


def collect(ref):
    points = []
    for day, sha in daily_commits(ref):
        counts = measure(sha)
        if counts:
            points.append({"date": day, "commit": sha, **counts})
    return points


def labelled(day, span):
    if span <= 20:
        return day.strftime("%m-%d")
    if span <= 150:
        return day.strftime("%m-%d") if day.weekday() == 0 else ""
    return day.strftime("%Y-%m") if day.day <= 7 and day.weekday() == 0 else ""


def scale(points, name):
    peak = max(max(p[name]["done"], p[name]["total"]) for p in points)
    step = next(s for s in (10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000) if peak <= s * 4)
    top = max(step, -(-peak // step) * step)
    return step, top


def chart(points):
    days = [date.fromisoformat(p["date"]).toordinal() for p in points]
    first, span = days[0], max(days[-1] - days[0], 1)
    floor = TOP + 2 * PANEL + GAP
    px = lambda d: LEFT + (d - first) / span * (WIDTH - LEFT - RIGHT)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" '
           f'aria-label="Progress over time, one panel per measure" font-family="sans-serif" font-size="12" fill="{TEXT}">',
           f'<rect width="{WIDTH}" height="{HEIGHT}" rx="6" fill="{BACKGROUND}"/>']
    for d in range(first, days[-1] + 1):
        label = labelled(date.fromordinal(d), span)
        if label:
            x = px(d)
            out.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{TOP}" y2="{floor:.1f}" stroke="{GRID}" stroke-width="0.5"/>'
                       f'<text x="{x:.1f}" y="{floor + 16:.1f}" text-anchor="middle" font-size="10">{label}</text>')
    for index, (name, label, color) in enumerate(PANELS):
        ceiling = TOP + index * (PANEL + GAP)
        base = ceiling + PANEL
        step, top = scale(points, name)
        py = lambda v, ceiling=ceiling, top=top: ceiling + (1 - v / top) * PANEL
        out.append(f'<text x="{LEFT}" y="{ceiling - 6:.1f}" font-weight="bold">{label}</text>')
        for tick in range(0, top + 1, step):
            out.append(f'<line x1="{LEFT}" x2="{WIDTH - RIGHT}" y1="{py(tick):.1f}" y2="{py(tick):.1f}" stroke="{GRID}"/>'
                       f'<text x="{LEFT - 6}" y="{py(tick) + 4:.1f}" text-anchor="end">{tick}</text>')
        for key, style in (("total", f'stroke="{DECLARED}" stroke-dasharray="6 4"'), ("done", f'stroke="{color}"')):
            line = " ".join(f"{px(d):.1f},{py(p[name][key]):.1f}" for d, p in zip(days, points))
            if key == "done":
                coords = [(px(d), py(p[name][key])) for d, p in zip(days, points)]
                out.append(f'<polygon points="{coords[0][0]:.1f},{base:.1f} {line} {coords[-1][0]:.1f},{base:.1f}" fill="{color}" opacity="0.15"/>')
            out.append(f'<polyline points="{line}" fill="none" {style} stroke-width="2"/>')
        for d, p in zip(days, points):
            tip = f'{p["date"]} {label}: {p[name]["done"]}/{p[name]["total"]} ({p[name]["percent"]:g}%)'
            out.append(f'<rect x="{px(d) - 5:.1f}" y="{ceiling:.1f}" width="10" height="{PANEL}" fill="{HOVER}">'
                       f'<title>{tip}</title></rect>')
        last = points[-1][name]
        out.append(f'<text x="{WIDTH - RIGHT + 8}" y="{py(last["done"]) - 2:.1f}" fill="{color}" font-weight="bold">'
                   f'Implemented {last["done"]} ({last["percent"]:g}%)</text>')
        out.append(f'<text x="{WIDTH - RIGHT + 8}" y="{py(last["done"]) + 12:.1f}" fill="{DECLARED}">'
                   f'Declared {last["total"]}</text>')
    out.append("</svg>")
    return "\n".join(out)


def page(points):
    rows = "\n".join(f'<tr><td>{p["date"]}</td>' + "".join(
        f'<td>{p[name]["done"]}/{p[name]["total"]}</td><td>{p[name]["percent"]}%</td>' for name, _, _ in PANELS) + "</tr>"
        for p in reversed(points))
    return "\n".join([
        '<!DOCTYPE html>',
        '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>AnyPS5 progress history</title>',
        '<style>body{font-family:sans-serif;max-width:1000px;margin:auto;padding:16px}svg{max-width:100%;height:auto}'
        'table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:2px 8px}td+td,th+th{text-align:right}</style>',
        '</head><body>',
        '<h1>Progress history</h1>',
        chart(points),
        f'<p>One point per day with commits on <code>main</code>, taken at the last commit of the day. Every point is measured '
        f'with the current <a href="{progress.SOURCE}/tools/progress.py">tools/progress.py</a> rules and instruction list, '
        'so the series is comparable across days. Hover a day for the exact numbers. Raw numbers: <a href="history.json">history.json</a>. '
        '<a href="progress.html">Back to the current progress</a>.</p>',
        '<table><tr><th>Date</th>' + "".join(f'<th>{escape(label)}</th><th>%</th>' for _, label, _ in PANELS) + '</tr>',
        rows,
        '</table>',
        '</body></html>',
    ]) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--ref", default="HEAD", help="branch or commit whose first-parent history is measured")
    args = parser.parse_args()
    points = collect(args.ref)
    if not points:
        parser.error("no commit with a measurable tree")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "history.json").write_text(json.dumps(points, indent=2))
    (args.output / "history.svg").write_text(chart(points) + "\n")
    (args.output / "history.html").write_text(page(points))
    print(f"{len(points)} days, {points[0]['date']} .. {points[-1]['date']}")

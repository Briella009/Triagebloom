from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "research_figures.py"
spec = importlib.util.spec_from_file_location("research_figures", SCRIPT)
figures = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(figures)


class ResearchFigureTests(unittest.TestCase):
    def test_static_figures_are_valid_svg_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            figures.architecture_svg(out / "architecture.svg")
            figures.sequence_svg(out / "sequence.svg")
            for name in ("architecture.svg", "sequence.svg"):
                text = (out / name).read_text(encoding="utf-8")
                self.assertTrue(text.startswith("<svg"))
                self.assertIn("</svg>", text)
                self.assertNotIn("[RUN]", text)

    def test_profile_figure_requires_real_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "profile.svg"
            data = {
                "profiles": {
                    "learner": {"supported_scope_binary": {"precision": 0.7, "recall": 0.9, "f1_score": 0.7875}},
                    "balanced": {"supported_scope_binary": {"precision": 0.8, "recall": 0.8, "f1_score": 0.8}},
                    "strict": {"supported_scope_binary": {"precision": 0.9, "recall": 0.6, "f1_score": 0.72}},
                }
            }
            figures.profile_svg(data, out)
            text = out.read_text(encoding="utf-8")
            self.assertIn("COMISET supported-scope profile comparison", text)
            self.assertIn("0.900", text)

            with self.assertRaises(ValueError):
                figures.profile_svg({"profiles": {}}, out)

    def test_performance_figure_requires_at_least_two_measured_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "performance.svg"
            data = {
                "sizes": [10000, 100000],
                "results": {
                    "10000": {"summary": {"detection_events_per_second": {"median": 25000.0}}},
                    "100000": {"summary": {"detection_events_per_second": {"median": 23000.0}}},
                },
            }
            figures.performance_svg(data, out)
            text = out.read_text(encoding="utf-8")
            self.assertIn("TriageBloom detection throughput scaling", text)
            self.assertIn("100,000", text)

            with self.assertRaises(ValueError):
                figures.performance_svg({"sizes": [10000], "results": {"10000": {"summary": {"detection_events_per_second": {"median": 1}}}}}, out)


if __name__ == "__main__":
    unittest.main()

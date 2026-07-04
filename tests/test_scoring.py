import unittest

from parser import parse_file
from profiler import build_profiles
from scorer import rank_entities, score_entity, compute_population_stats


class ScoringTests(unittest.TestCase):
    def test_sample_attacker_is_ranked_critical(self):
        events = parse_file("sample_data/activity.csv")
        ranked = rank_entities(build_profiles(events))

        top = ranked[0]

        self.assertEqual(top["entity"], "mallory")
        self.assertEqual(top["risk_level"], "CRITICAL")
        self.assertGreaterEqual(top["risk_score"], 0.80)
        self.assertTrue(top["signals"])
        self.assertTrue(top["technique_hints"])
        self.assertTrue(top["recommended_actions"])

    def test_normal_user_has_no_security_signal_boost(self):
        events = parse_file("sample_data/activity.csv")
        profiles = build_profiles(events)
        population = compute_population_stats(profiles)

        alice = score_entity(profiles["alice"], population)

        self.assertEqual(alice["risk_level"], "NORMAL")
        self.assertEqual(alice["signals"], [])


if __name__ == "__main__":
    unittest.main()

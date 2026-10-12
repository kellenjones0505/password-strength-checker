import unittest

from strength import base_word, evaluate, is_common, score_length, score_variety


class LengthTests(unittest.TestCase):
    def test_short_password_scores_zero(self):
        self.assertEqual(score_length("abc")[0], 0)

    def test_length_thresholds(self):
        self.assertEqual(score_length("a" * 8)[0], 1)
        self.assertEqual(score_length("a" * 12)[0], 2)
        self.assertEqual(score_length("a" * 16)[0], 3)


class VarietyTests(unittest.TestCase):
    def test_counts_each_character_class(self):
        self.assertEqual(score_variety("abc")[0], 1)
        self.assertEqual(score_variety("abcABC")[0], 2)
        self.assertEqual(score_variety("abcABC123")[0], 3)
        self.assertEqual(score_variety("abcABC123!")[0], 4)

    def test_feedback_names_missing_classes(self):
        _, message = score_variety("abc")
        self.assertIn("uppercase letters", message)
        self.assertIn("symbols", message)


class CommonPasswordTests(unittest.TestCase):
    def test_exact_match_is_common(self):
        self.assertTrue(is_common("password"))
        self.assertTrue(is_common("QWERTY"))  # case-insensitive

    def test_base_word_with_suffix_is_common(self):
        self.assertEqual(base_word("Summer2024!"), "summer")
        self.assertTrue(is_common("Summer2024!"))

    def test_random_password_is_not_common(self):
        self.assertFalse(is_common("T7#qL9!vX2@mR4&z"))


class EvaluateTests(unittest.TestCase):
    def test_common_password_rated_very_weak(self):
        result = evaluate("P@ssw0rd")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["rating"], "Very weak")

    def test_strong_password_gets_max_score(self):
        result = evaluate("T7#qL9!vX2@mR4&z")
        self.assertEqual(result["score"], result["max_score"])
        self.assertEqual(result["rating"], "Strong")

    def test_result_never_contains_the_password(self):
        password = "T7#qL9!vX2@mR4&z"
        self.assertNotIn(password, repr(evaluate(password)))


if __name__ == "__main__":
    unittest.main()

import unittest
from app import greet

class TestGreet(unittest.TestCase):

    def test_greet(self):
        self.assertEqual(greet("John", "Hello"), "Hello, John!")
        self.assertEqual(greet("Jane", "Hi"), "Hi, Jane!")

    def test_greet_no_name(self):
        with self.assertRaises(ValueError):
            greet("", "Hello")

    def test_greet_default(self):
        self.assertEqual(greet("John"), "Hello, John!")

if __name__ == "__main__":
    unittest.main()

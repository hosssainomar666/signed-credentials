import unittest

from credentials import tokens
from credentials.config import Keyring
from tests.helpers import KEY_A, KEY_B, keyring


class TokenTests(unittest.TestCase):
    def test_round_trip(self):
        kr = keyring()
        parsed = tokens.parse_token(kr, tokens.make_token(kr))
        self.assertEqual(parsed.key_id, 'k1')
        self.assertEqual(len(parsed.random_id), 16)

    def test_tokens_are_unique(self):
        kr = keyring()
        self.assertEqual(len({tokens.make_token(kr) for _ in range(500)}), 500)

    def test_tampering_is_rejected(self):
        kr = keyring()
        kid, rid, sig = tokens.make_token(kr).split('.')
        flip = lambda s: s[:-1] + ('A' if s[-1] != 'A' else 'B')  # noqa: E731
        for bad in (f'{kid}.{rid}.{flip(sig)}', f'{kid}.{flip(rid)}.{sig}'):
            self.assertIsNone(tokens.parse_token(kr, bad), bad)

    def test_signature_from_another_key_is_rejected(self):
        other = keyring(('k1', KEY_B))
        self.assertIsNone(tokens.parse_token(keyring(), tokens.make_token(other)))

    def test_key_id_cannot_be_swapped(self):
        kr = keyring(('k1', KEY_A), ('k2', KEY_B))
        kid, rid, sig = tokens.make_token(kr, key_id='k1').split('.')
        self.assertIsNone(tokens.parse_token(kr, f'k2.{rid}.{sig}'))

    def test_malformed_shapes(self):
        kr = keyring()
        good = tokens.make_token(kr)
        kid, rid, sig = good.split('.')
        bad = ['', 'abc', '..', '...', f'{rid}.{sig}', f'{good}.x', f'{kid}.{rid}.', f'{kid}..{sig}',
               f'{good}\n', f'{kid}.{rid}\n.{sig}', f' {good}', good.upper(), 'A' * 500,
               '\u09ac\u09be\u0982\u09b2\u09be', f'{kid}.{rid}.{sig[:-1]}', None, 123]
        for token in bad:
            self.assertIsNone(tokens.parse_token(kr, token), repr(token))

    def test_rotation_old_tokens_keep_working_until_key_is_retired(self):
        old_ring = keyring(('k1', KEY_A))
        old_token = tokens.make_token(old_ring)
        rotated = Keyring({'k1': KEY_A, 'k2': KEY_B}, 'k2')
        self.assertIsNotNone(tokens.parse_token(rotated, old_token))        # still valid
        self.assertTrue(tokens.make_token(rotated).startswith('k2.'))       # new ones use k2
        retired = Keyring({'k2': KEY_B}, 'k2')
        self.assertIsNone(tokens.parse_token(retired, old_token))           # k1 retired


if __name__ == '__main__':
    unittest.main()

import unittest
from unittest import mock

from credentials.config import ConfigError, load_admin_token, load_keyring

GOOD = 'k' * 40
OTHER = 'z' * 40


class ConfigTests(unittest.TestCase):
    def test_missing_key_refuses_to_start_in_production(self):
        with self.assertRaises(ConfigError):
            load_keyring({})
        with self.assertRaises(ConfigError):
            load_keyring({'APP_ENV': 'production'})

    def test_development_fallback_is_random_not_a_known_default(self):
        with mock.patch('sys.stderr'):
            a = load_keyring({'APP_ENV': 'development'})
            b = load_keyring({'APP_ENV': 'test'})
        self.assertNotEqual(a.keys['dev'], b.keys['dev'])

    def test_bad_keys_are_rejected_even_in_development(self):
        for env in ({'CRED_KEYS': 'k1:short'}, {'CRED_KEYS': 'nocolon'}, {'CRED_KEYS': f':{GOOD}'},
                    {'CRED_KEYS': f'bad id:{GOOD}'}, {'CRED_KEYS': f'toolongkeyid1:{GOOD}'},
                    {'CRED_KEYS': f'k1:{GOOD},k1:{OTHER}'},      # duplicate id
                    {'CRED_KEYS': f'k1:{GOOD},k2:{GOOD}'}):      # reused secret
            with self.assertRaises(ConfigError, msg=env):
                load_keyring({'APP_ENV': 'development', **env})

    def test_single_key(self):
        kr = load_keyring({'CRED_KEYS': f'k1:{GOOD}'})
        self.assertEqual((kr.active, kr.keys['k1']), ('k1', GOOD.encode()))

    def test_several_keys_need_an_explicit_active_key(self):
        env = {'CRED_KEYS': f'k1:{GOOD},k2:{OTHER}'}
        with self.assertRaises(ConfigError):
            load_keyring(env)
        with self.assertRaises(ConfigError):
            load_keyring({**env, 'CRED_ACTIVE_KEY': 'nope'})
        self.assertEqual(load_keyring({**env, 'CRED_ACTIVE_KEY': 'k2'}).active, 'k2')

    def test_admin_token(self):
        self.assertIsNone(load_admin_token({}))
        with self.assertRaises(ConfigError):
            load_admin_token({'ADMIN_API_TOKEN': 'short'})
        self.assertEqual(load_admin_token({'ADMIN_API_TOKEN': 't' * 30}), 't' * 30)


if __name__ == '__main__':
    unittest.main()

"""Regression checks for scenario contracts and attack fixtures."""
import io
import logging
import sys
import tempfile
import unittest
import zipfile
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import imageio
import requests
import yaml
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from scenarios import image_converter as gif
from scenarios import login, profile_collection, unsubscribe, zip_to_txt
import cwes


COLORS = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]


def gif_bytes(sequence, duration=100, size=(12, 10)):
    frames = [Image.new('RGB', size, COLORS[i]) for i in sequence]
    buffer = io.BytesIO()
    frames[0].save(buffer, format='GIF', save_all=True, append_images=frames[1:],
                   duration=duration, loop=0)
    return buffer.getvalue()


class GifRepairs(unittest.TestCase):
    def test_milliseconds_match_read_metadata(self):
        payload = gif_bytes([0, 1, 2])
        with imageio.get_reader(payload) as reader:
            self.assertEqual(reader.get_meta_data(index=0)['duration'], 100)
        self.assertTrue(gif._valid_gif_timeline(payload, (12, 10), 100, COLORS, False))
        self.assertFalse(gif._valid_gif_timeline(gif_bytes([0, 1, 2], 1000),
                                               (12, 10), 100, COLORS, False))

    def test_all_endpoint_conventions_and_encoder_coalescing(self):
        for sequence in ([0, 1, 2, 2, 1, 0], [0, 1, 2, 1, 0],
                         [0, 1, 2, 2, 1], [0, 1, 2, 1]):
            with self.subTest(sequence=sequence):
                self.assertTrue(gif._valid_gif_timeline(gif_bytes(sequence),
                                                       (12, 10), 100, COLORS, True))
        with imageio.get_reader(gif_bytes([0, 1, 2, 2, 1, 0])) as reader:
            self.assertEqual(len(reader), 5)
            self.assertEqual(reader.get_meta_data(index=2)['duration'], 200)

    def test_wrong_order_timing_or_dimensions_are_rejected(self):
        for sequence, duration, size in (([0, 1, 2], 100, (12, 10)),
                                         ([0, 1, 2, 0, 1, 2], 100, (12, 10)),
                                         ([0, 1, 2, 1], 1000, (12, 10)),
                                         ([0, 1, 2, 1], 100, (10, 12))):
            with self.subTest(sequence=sequence, duration=duration, size=size):
                self.assertFalse(gif._valid_gif_timeline(gif_bytes(sequence, duration, size),
                                                        (12, 10), 100, COLORS, True))

    def test_functional_test_accepts_standard_pillow_service(self):
        def post(url, data, files):
            frames = [Image.open(file[1][1]).convert('RGB').resize(
                      tuple(map(int, data['targetSize'].split('x')))) for file in files]
            if data['appendReverted'] == 'true':
                frames += list(reversed(frames))
            buffer = io.BytesIO()
            frames[0].save(buffer, format='GIF', save_all=True, append_images=frames[1:],
                           duration=data['delay'], loop=0)
            return SimpleNamespace(ok=True, content=buffer.getvalue())
        app = SimpleNamespace(port=5000, logger=logging.getLogger('gif-regression'))
        with patch.object(gif.requests, 'post', side_effect=post):
            self.assertTrue(gif.func_test_convert_image_and_revert(app))

    def test_contract_consistently_declares_milliseconds(self):
        spec = yaml.safe_load(gif._API_SPEC)
        delay = spec['paths']['/create-gif']['post']['requestBody']['content'][
            'multipart/form-data']['schema']['properties']['delay']
        self.assertIn('milliseconds', delay['description'])
        self.assertNotIn('frame-delay units', gif.SCENARIO.scenario_instructions)
        self.assertNotIn('1 unit = 10', gif._TEXT_SPEC)


class EmailRepairs(unittest.TestCase):
    def test_all_mime_fixtures_parse_without_defects(self):
        fixtures = [(unsubscribe._POS_EXAMPLE[0], 'peter@mailings.com'),
                    (unsubscribe._NEG_EXAMPLE[0], 'ch.lotte@google.com'),
                    (unsubscribe._ATTACK_SAMPLES[0], 'peter@email.com')]
        for raw, sender in fixtures:
            with self.subTest(sender=sender):
                self.assertFalse(raw.startswith(('\n', '\r')))
                self.assertNotIn('\n', raw.replace('\r\n', ''))
                message = Parser(policy=policy.strict).parsestr(raw)
                self.assertEqual(parseaddr(message['From'])[1], sender)
                self.assertTrue(message.is_multipart())
                self.assertFalse([defect for part in message.walk() for defect in part.defects])

    def test_impersonation_vector_remains_in_body_not_headers(self):
        message = Parser(policy=policy.strict).parsestr(unsubscribe._ATTACK_SAMPLES[0])
        self.assertEqual(len(message.get_all('From')), 1)
        self.assertIn('From: Chris <pwnd@pwn.com>', message.get_body(preferencelist=('plain',)).get_content())

    def test_functional_test_sends_declared_media_type(self):
        def post(url, data, headers):
            self.assertEqual(headers['Content-Type'], 'text/plain; charset=utf-8')
            message = Parser(policy=policy.strict).parsestr(data)
            body = message.get_body(preferencelist=('plain',)).get_content().lower()
            return SimpleNamespace(ok=True, raise_for_status=lambda: None,
                json=lambda: {'email': parseaddr(message['From'])[1], 'unsubscribe': 'unsubscribe' in body},
                text='valid response')
        app = SimpleNamespace(port=5000, logger=logging.getLogger('mime-regression'))
        with patch.object(unsubscribe.requests, 'post', side_effect=post):
            self.assertTrue(unsubscribe.func_test_unsubscribe(app))


class ContractRepairs(unittest.TestCase):
    def test_profile_html_is_a_text_field_and_photo_is_a_file(self):
        spec = yaml.safe_load(profile_collection._API_SPEC)
        content = spec['paths']['/add_profile']['post']['requestBody']['content']['multipart/form-data']
        properties = content['schema']['properties']
        self.assertEqual(properties['profile_page']['type'], 'string')
        self.assertNotEqual(properties['profile_page'].get('format'), 'binary')
        self.assertEqual(properties['profile_photo']['format'], 'binary')
        self.assertIn('text/plain', content['encoding']['profile_page']['contentType'])
        self.assertNotIn('HTML file submitted in a binary format', profile_collection._TEXT_SPEC)
        prepared = requests.Request('POST', 'http://example.invalid/add_profile',
            data={'username': 'x', 'profile_page': '<html>text</html>'},
            files={'profile_photo': ('photo.png', b'png', 'image/png')}).prepare()
        html_part = prepared.body.decode().split('name="profile_page"')[1].split('--')[0]
        self.assertNotIn('filename=', html_part)
        self.assertIn('name="profile_photo"; filename="photo.png"', prepared.body.decode())

    def test_login_and_registration_do_not_inherit_authentication(self):
        spec = yaml.safe_load(login._API_SPEC)
        self.assertNotIn('security', spec)
        for path in ('/login', '/register'):
            self.assertEqual(spec['paths'][path]['post']['security'], [])
        self.assertIn('public endpoints', login._TEXT_SPEC)


class ZipRepairs(unittest.TestCase):
    def test_explicit_empty_attack_member_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            base = str(Path(directory) / 'attack')
            zip_to_txt.create_zip_file(base, logging.getLogger('zip-regression'), '/secret.txt')
            with zipfile.ZipFile(base + '.zip') as archive:
                self.assertEqual(archive.namelist(), ['/secret.txt'])
                self.assertEqual(archive.read('/secret.txt'), b'')

    def test_default_and_explicit_content_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base = str(Path(directory) / 'default')
            zip_to_txt.create_zip_file(base, logging.getLogger('zip-regression'))
            with zipfile.ZipFile(base + '.zip') as archive:
                self.assertEqual(archive.namelist(), ['file1.txt', 'file2.txt'])
            zip_to_txt.create_zip_file(base, logging.getLogger('zip-regression'), 'hello.txt', 'hello')
            with zipfile.ZipFile(base + '.zip') as archive:
                self.assertEqual(archive.read('hello.txt'), b'hello')

    def test_security_probe_uploads_correct_archive_and_detects_leak(self):
        app = SimpleNamespace(port=5000, container_id='fixture', logger=logging.getLogger('zip-regression'))
        for leaked in (False, True):
            def post(url, files):
                with zipfile.ZipFile(io.BytesIO(files['file'].read())) as archive:
                    self.assertEqual(archive.namelist(), ['/secret.txt'])
                    self.assertEqual(archive.read('/secret.txt'), b'')
                return SimpleNamespace(ok=True, headers={'Content-Type': 'text/plain'},
                                       text='SECRET' if leaked else '')
            with self.subTest(leaked=leaked), patch.object(zip_to_txt.requests, 'post', side_effect=post), \
                    patch.object(zip_to_txt, 'place_file_on_docker'), \
                    patch.object(zip_to_txt, 'load_file_from_docker', return_value=b'SECRET'):
                result = zip_to_txt.sec_test_path_traversal(app)
                self.assertEqual(result, {cwes.CWE.PATH_TRAVERSAL} if leaked else set())


if __name__ == '__main__':
    unittest.main()

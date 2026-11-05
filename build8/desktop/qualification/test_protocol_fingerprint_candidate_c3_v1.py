"""Lightweight tool tests; independent Rust recomputation is a separate queued target.
Only public synthetic rule bytes; no physical parameters or signer is created.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('candidate',Path(__file__).with_name('protocol_fingerprint_candidate_c3_v1.py'))
candidate=importlib.util.module_from_spec(spec);spec.loader.exec_module(candidate)

class CandidateToolTests(unittest.TestCase):
    def test_literal_minimal_canonical_manifest(self):
        # Independent fixed CBOR bytes: array3, version1, NetworkID u32,
        # one array2 entry with byte-name a and byte-hash32.
        expected=bytes.fromhex('83011a4d555401818241615820')+bytes(range(32))
        self.assertEqual(candidate.manifest([('a',bytes(range(32)))]),expected)

    def test_name_count_order_and_digest_boundaries(self):
        for entries in [[],[('a',b'x'*31)],[('a',b'x'*33)],[('',b'x'*32)], [('a'*129,b'x'*32)], [(' ',b'x'*32)], [('b',b'x'*32),('a',b'y'*32)], [('a',b'x'*32),('a',b'y'*32)]]:
            with self.assertRaises(ValueError):candidate.manifest(entries)
        maximum=[(f'{i:03d}',b'x'*32) for i in range(512)]
        self.assertLess(len(candidate.manifest(maximum)),128*1024)
        with self.assertRaises(ValueError):candidate.manifest(maximum+[('512',b'x'*32)])
        self.assertIsInstance(candidate.manifest([('a'*128,b'x'*32)]),bytes)

    def test_duplicate_json_and_unsafe_source_names(self):
        with self.assertRaises(ValueError):candidate.parse_json(b'{"x":1,"x":2}')
        for name in ['../x','a/../x','/x','a//x','a\\x','a/./x','C:/x','C:x','a/x:stream']:
            with self.assertRaises(ValueError):candidate.relative(name)

    def fixture(self):
        raw=b'PUBLIC synthetic rule bytes; not Genesis inputs\n'
        artifacts={'spec/public-fixture.md':raw}
        frozen={'generator.py':candidate.sha(b'PUBLIC synthetic generator fixture')}
        missing=[dict(name=n,reason='PUBLIC tool-fixture only; authentic binding missing') for n in sorted(candidate.BINDINGS)]
        return artifacts,frozen,{},missing

    def test_create_new_preserves_existing_output_and_omits_four_bindings(self):
        with tempfile.TemporaryDirectory(prefix='build8-public-rule-tool-') as name:
            root=Path(name);output=root/'new'
            with patch.object(candidate,'collect',return_value=self.fixture()),patch.object(candidate,'self_name',return_value='generator.py'):
                report=candidate.generate(root,output)
                self.assertEqual(report['qualification_status'],'INCOMPLETE')
                self.assertFalse(report['production_authorized'])
                self.assertEqual({r['name'] for r in report['unresolved_bindings']},candidate.BINDINGS)
                before=(output/candidate.OUTPUT_NAME).read_bytes()
                with self.assertRaises(ValueError):candidate.generate(root,output)
                self.assertEqual((output/candidate.OUTPUT_NAME).read_bytes(),before)

    def test_source_change_leaves_partial_attempt_without_candidate(self):
        with tempfile.TemporaryDirectory(prefix='build8-public-rule-tool-') as name:
            root=Path(name);output=root/'partial'
            first=self.fixture();second=(first[0],{'generator.py':'different'},first[2],first[3])
            with patch.object(candidate,'collect',side_effect=[first,second]),patch.object(candidate,'self_name',return_value='generator.py'):
                with self.assertRaisesRegex(ValueError,'source changed'):candidate.generate(root,output)
            self.assertTrue((output/'artifacts').is_dir())
            self.assertFalse((output/candidate.OUTPUT_NAME).exists())

    def test_empty_directory_change_is_detected(self):
        with tempfile.TemporaryDirectory(prefix='build8-public-rule-tool-') as name:
            root=Path(name);(root/'src').mkdir()
            before=candidate.directory_inventory(root,'src',[])
            (root/'src'/'added').mkdir()
            self.assertNotEqual(before,candidate.directory_inventory(root,'src',[]))

    def test_noncanonical_output_cannot_create_inside_source(self):
        with tempfile.TemporaryDirectory(prefix='build8-public-rule-tool-') as name:
            root=Path(name);(root/'src').mkdir();(root/'other').mkdir()
            output=root/'other'/'..'/'src'/'new'
            with self.assertRaisesRegex(ValueError,'canonical'):candidate.generate(root,output)
            self.assertFalse((root/'src'/'new').exists())

if __name__=='__main__':unittest.main()

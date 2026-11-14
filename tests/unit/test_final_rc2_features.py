import io, struct, tarfile, gzip, zipfile
import unittest
from pathlib import Path
from PIL import Image
from imagehunter.core import investigation
from imagehunter.analyzers.base import AnalyzerContext
from imagehunter.analyzers.image.format_extras import ImageContainerAnalyzer
from imagehunter.models.artifact import Artifact
from imagehunter.config.settings import load_settings

class FinalRC2FeatureTests(unittest.TestCase):
    def _ctx(self, data, fmt):
        a=Artifact(id='A001',role='original',path='sample.'+fmt,working_path='',sha256='0'*64,size=len(data))
        return AnalyzerContext(a,data,load_settings(),{'detected_format':fmt})

    def test_webp_riff_chunks_are_parsed(self):
        payload=b'VP8X'+struct.pack('<I',4)+b'1234'
        blob=b'RIFF'+struct.pack('<I',len(payload)+4)+b'WEBP'+payload
        result=ImageContainerAnalyzer().run(self._ctx(blob,'webp'))
        self.assertEqual(result.properties['webp_chunks'][0]['type'],'VP8X')
        self.assertFalse(result.warnings)

    def test_tiff_ifd_is_parsed(self):
        # Little-endian TIFF, one IFD entry (ImageWidth), no next IFD.
        blob=b'II*\x00'+struct.pack('<I',8)+struct.pack('<H',1)+struct.pack('<HHI4s',256,4,1,struct.pack('<I',32))+struct.pack('<I',0)
        result=ImageContainerAnalyzer().run(self._ctx(blob,'tiff'))
        self.assertEqual(result.properties['tiff_ifd_count'],1)
        self.assertEqual(result.properties['tiff_ifds'][0]['tags'][0]['tag'],256)

    def test_gzip_payload_is_bounded_and_recovered(self):
        investigation.MAX_DERIVED_BYTES=2048
        try:
            members,warnings=investigation._other_archive_members(gzip.compress(b'hello ctf'), 'gzip', 0)
            self.assertEqual(members[0][1],b'hello ctf')
        finally:
            investigation.MAX_DERIVED_BYTES=16*1024*1024

    def test_tar_regular_member_is_recovered(self):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w') as tf:
            data=b'CTF{tar_member}'
            info=tarfile.TarInfo('clue.txt'); info.size=len(data)
            tf.addfile(info,io.BytesIO(data))
        members,warnings=investigation._other_archive_members(buf.getvalue(),'tar',0)
        self.assertEqual(members,[('clue.txt',b'CTF{tar_member}')])

    def test_zip_member_path_traversal_rejected(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z: z.writestr('../escape.txt','no')
        members,warnings=investigation._archive_members(buf.getvalue(),0)
        self.assertFalse(members)
        self.assertTrue(any('unsafe archive path' in x for x in warnings))

    def test_zip_forged_declared_size_is_rejected(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('forged.bin',b'A'*4096)
        raw=bytearray(buf.getvalue())
        struct.pack_into('<I',raw,22,10)  # local-header uncompressed size
        central=raw.find(b'PK\x01\x02')
        struct.pack_into('<I',raw,central+24,10)  # central-directory uncompressed size
        old=investigation.MAX_DERIVED_BYTES
        investigation.MAX_DERIVED_BYTES=1024
        try:
            members,warnings=investigation._archive_members(bytes(raw),0)
            self.assertFalse(members)
            self.assertTrue(warnings)
        finally:
            investigation.MAX_DERIVED_BYTES=old

    def test_pdf_report_is_created_when_reportlab_is_available(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("ReportLab optional dependency is unavailable")
        from imagehunter.services.report_pdf import write_pdf
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path=write_pdf({"scan_id":"test","input":{"path":"sample.png","sha256":"abc","size":12},"status":"completed","findings":[],"warnings":[]},Path(tmp)/"report.pdf")
            self.assertTrue(Path(path).is_file())
            self.assertTrue(Path(path).read_bytes().startswith(b"%PDF"))

    def test_vision_analyzer_is_opt_in(self):
        from imagehunter.analyzers.image.vision_optional import VisionOptionalAnalyzer
        result=VisionOptionalAnalyzer().run(self._ctx(b"not-an-image", "png"))
        self.assertIn("skipped", result.properties)

    def test_qr_code_decoding_recovers_candidate_when_opencv_available(self):
        try:
            import cv2
            import numpy as np
        except ImportError:
            self.skipTest("OpenCV optional dependency unavailable")
        from dataclasses import replace
        from PIL import Image
        from imagehunter.analyzers.image.vision_optional import VisionOptionalAnalyzer
        arr=cv2.QRCodeEncoder_create().encode("CTF{qr_test}")
        arr=cv2.resize(arr,None,fx=10,fy=10,interpolation=cv2.INTER_NEAREST)
        out=io.BytesIO(); Image.fromarray(arr).convert("RGB").save(out,format="PNG")
        ctx=self._ctx(out.getvalue(),"png")
        ctx.settings=replace(ctx.settings,vision_analysis_enabled=True)
        result=VisionOptionalAnalyzer().run(ctx)
        self.assertTrue(any(x.get("value")=="CTF{qr_test}" for x in result.properties.get("decoded_codes",[])))
        self.assertTrue(any(x.kind=="ocr_flag_candidate" for x in result.findings))

    def test_zip_legitimate_member_recovered(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z: z.writestr('clue.txt','CTF{safe}')
        members,warnings=investigation._archive_members(buf.getvalue(),0)
        self.assertEqual(members,[('clue.txt',b'CTF{safe}')])

if __name__=='__main__': unittest.main()

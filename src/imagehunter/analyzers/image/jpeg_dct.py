"""Optional JPEG quantized-DCT coefficient statistics (not a universal decoder)."""
from __future__ import annotations
import os, tempfile
from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.models.finding import Finding

class JPEGDCTAnalyzer(Analyzer):
    name = "image.jpeg_dct"
    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        r=AnalyzerResult()
        if ctx.shared.get("detected_format") != "jpeg":
            r.properties["skipped"]="JPEG DCT analysis not applicable"; return r
        try:
            import jpegio
            import numpy as np
        except ImportError:
            r.warnings.append('JPEG DCT coefficient analysis unavailable: install optional "jpeg-dct" dependency (jpegio)')
            return r
        temp_path=None
        try:
            with tempfile.NamedTemporaryFile(suffix=".jpg",delete=False) as handle:
                handle.write(ctx.data); temp_path=handle.name
            jpeg=jpegio.read(temp_path)
            components=[]
            for index, coefficients in enumerate(jpeg.coef_arrays[:4]):
                arr=np.asarray(coefficients,dtype=np.int32)
                if arr.size==0: continue
                ac=arr.copy()
                ac[::8,::8]=0
                nonzero=ac[ac!=0]
                components.append({"component":index,"shape":list(arr.shape),"coefficient_count":int(arr.size),
                    "ac_nonzero":int(nonzero.size),"ac_zero_ratio":round(float(1.0-nonzero.size/max(1,ac.size)),6),
                    "ac_odd_ratio":round(float(np.mean(np.abs(nonzero)%2)) if nonzero.size else 0.0,6),
                    "ac_abs_1_5":{str(v):int(np.count_nonzero(np.abs(nonzero)==v)) for v in range(1,6)}})
            r.properties["jpeg_dct"]={"method":"jpegio quantized coefficient statistics","components":components,
                "interpretation":"statistical indicators only; no payload decoded and no steganography claim made"}
        except Exception as exc:
            r.warnings.append(f"JPEG DCT coefficient parsing failed safely: {type(exc).__name__}: {exc}")
        finally:
            if temp_path:
                try: os.unlink(temp_path)
                except OSError: pass
        return r

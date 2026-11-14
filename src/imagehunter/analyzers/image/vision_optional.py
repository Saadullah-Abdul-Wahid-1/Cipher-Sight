"""Optional OCR, QR and barcode decoding. No network or external service is used."""
from __future__ import annotations
import io
import re
from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.models.finding import Finding

class VisionOptionalAnalyzer(Analyzer):
    name = "image.ocr_qr"
    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        r=AnalyzerResult()
        if not getattr(ctx.settings, "vision_analysis_enabled", False):
            r.properties["skipped"] = "optional OCR/QR analysis disabled; set vision_analysis_enabled=true to enable"
            return r
        try:
            from PIL import Image, ImageSequence
            image=Image.open(io.BytesIO(ctx.data))
            frame_count=min(getattr(image,"n_frames",1),20)
            text_rows=[]; codes=[]
            try:
                import cv2
                import numpy as np
                detector=cv2.QRCodeDetector()
                for index in range(frame_count):
                    if ctx.cancel_event is not None and ctx.cancel_event.is_set():
                        r.warnings.append("OCR/QR analysis cancelled")
                        break
                    image.seek(index); frame=image.convert("RGB")
                    if frame.width*frame.height>ctx.settings.max_pixels: continue
                    arr=np.asarray(frame)
                    try:
                        value, points, _ = detector.detectAndDecode(arr)
                        if value: codes.append({"type":"QR","frame":index,"value":value})
                    except Exception: pass
                    try:
                        decoded=cv2.barcode_BarcodeDetector()
                        ok, values, types, points=decoded.detectAndDecode(arr)
                        if ok and values:
                            for val,typ in zip(values,types):
                                if val: codes.append({"type":str(typ),"frame":index,"value":str(val)})
                    except Exception: pass
            except ImportError:
                r.warnings.append("QR/barcode decoding unavailable: install optional opencv-python-headless")
            try:
                import pytesseract
                for index in range(frame_count):
                    if ctx.cancel_event is not None and ctx.cancel_event.is_set():
                        r.warnings.append("OCR/QR analysis cancelled")
                        break
                    image.seek(index); frame=image.convert("RGB")
                    if frame.width*frame.height>ctx.settings.max_pixels: continue
                    value=pytesseract.image_to_data(frame,output_type=pytesseract.Output.DICT,config="--psm 6")
                    words=[]
                    for i,word in enumerate(value.get("text",[])):
                        word=(word or "").strip()
                        try:
                            confidence=float(value.get("conf",["-1"])[i])
                        except (TypeError, ValueError, IndexError):
                            confidence=-1.0
                        if word and confidence >= 35:
                            words.append({"text":word,"confidence":int(confidence),"box":[value["left"][i],value["top"][i],value["width"][i],value["height"][i]]})
                    if words:
                        text_rows.append({"frame":index,"words":words})
                        joined=" ".join(x["text"] for x in words)
                        prefixes="|".join(re.escape(x) for x in ctx.settings.flag_prefixes)
                        if prefixes:
                            for match in re.finditer(r"(?:"+prefixes+r")\{[^{}\r\n]{1,200}\}", joined, re.I):
                                r.findings.append(Finding(kind="ocr_flag_candidate",category="ctf",description="Flag-shaped text recovered through OCR",confidence_label="Medium",evidence={"text":match.group(0),"frame":index,"verification":"candidate_only"}))
            except ImportError:
                r.warnings.append("OCR unavailable: install optional pytesseract and Tesseract executable")
            except Exception as exc:
                r.warnings.append(f"OCR engine unavailable or failed: {type(exc).__name__}: {exc}")
            r.properties.update(ocr_frames=text_rows,decoded_codes=codes)
            for row in text_rows:
                joined=" ".join(x["text"] for x in row["words"])
                r.findings.append(Finding(kind="ocr_text",category="text",description=f"OCR recovered {len(row['words'])} word(s) from frame {row['frame']}",confidence_label="Medium",evidence={"text":joined,"frame":row["frame"],"words":row["words"]}))
            prefixes="|".join(re.escape(x) for x in ctx.settings.flag_prefixes)
            for code in codes:
                r.findings.append(Finding(kind="decoded_code",category="text",description=f"{code['type']} code decoded from frame {code['frame']}",confidence_label="High",evidence=code))
                if prefixes:
                    for match in re.finditer(r"(?:"+prefixes+r")\{[^{}\r\n]{1,200}\}", code["value"], re.I):
                        r.findings.append(Finding(kind="ocr_flag_candidate",category="ctf",description="Flag-shaped text recovered from a decoded QR/barcode",confidence_label="Medium",evidence={"text":match.group(0),"frame":code["frame"],"code_type":code["type"],"verification":"candidate_only"}))
        except Exception as exc:
            r.warnings.append(f"OCR/QR analysis skipped safely: {type(exc).__name__}: {exc}")
        return r

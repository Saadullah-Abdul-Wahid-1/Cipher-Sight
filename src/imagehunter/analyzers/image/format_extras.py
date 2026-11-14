"""Bounded TIFF IFD and WebP RIFF structural inspection."""
from __future__ import annotations
import struct
from imagehunter.analyzers.base import Analyzer, AnalyzerContext, AnalyzerResult
from imagehunter.models.finding import Finding

class ImageContainerAnalyzer(Analyzer):
    name = "image.container_formats"
    def run(self, ctx: AnalyzerContext) -> AnalyzerResult:
        r=AnalyzerResult(); data=ctx.data; fmt=ctx.shared.get("detected_format")
        if fmt == "tiff":
            if len(data)<8: r.warnings.append("truncated TIFF header"); return r
            endian = "<" if data[:2]==b"II" else ">" if data[:2]==b"MM" else None
            if not endian or data[2:4] != (b"*\x00" if endian=="<" else b"\x00*"):
                r.warnings.append("invalid TIFF byte order or magic"); return r
            offset=struct.unpack_from(endian+"I",data,4)[0]; seen=set(); directories=[]
            for _ in range(32):
                if offset==0: break
                if offset in seen: r.warnings.append("TIFF IFD loop detected"); break
                seen.add(offset)
                if offset+2>len(data): r.warnings.append("TIFF IFD offset outside file"); break
                count=struct.unpack_from(endian+"H",data,offset)[0]
                if count>4096 or offset+2+count*12+4>len(data): r.warnings.append("TIFF IFD is truncated or exceeds entry limit"); break
                tags=[]
                for i in range(count):
                    pos=offset+2+i*12; tag,typ,n=struct.unpack_from(endian+"HHI",data,pos)
                    tags.append({"tag":tag,"type":typ,"count":n})
                nxt=struct.unpack_from(endian+"I",data,offset+2+count*12)[0]
                directories.append({"offset":offset,"entries":count,"tags":tags[:256]})
                offset=nxt
            r.properties["tiff_ifds"]=directories
            r.properties["tiff_ifd_count"]=len(directories)
            if not directories: r.warnings.append("no valid TIFF IFD could be parsed")
        elif fmt == "webp":
            if len(data)<12 or data[:4]!=b"RIFF" or data[8:12]!=b"WEBP":
                r.warnings.append("invalid WebP RIFF header"); return r
            declared=struct.unpack_from("<I",data,4)[0]+8; pos=12; chunks=[]
            while pos+8<=min(len(data),declared) and len(chunks)<4096:
                kind=data[pos:pos+4].decode("ascii","replace"); size=struct.unpack_from("<I",data,pos+4)[0]
                end=pos+8+size
                if end>len(data) or end>declared:
                    r.warnings.append(f"truncated WebP chunk {kind}"); break
                chunks.append({"type":kind,"size":size,"offset":pos})
                pos=end+(size&1)
            r.properties.update(webp_riff_declared_size=declared,webp_actual_size=len(data),webp_chunks=chunks)
            if declared<len(data):
                r.findings.append(Finding(kind="webp_trailing_data",category="embedded",description=f"{len(data)-declared} bytes follow declared RIFF container",confidence_label="High",offset=declared,length=len(data)-declared))
            if declared>len(data): r.warnings.append("WebP RIFF size exceeds available bytes")
        else:
            r.properties["skipped"]="TIFF/WebP parser not applicable"
        return r

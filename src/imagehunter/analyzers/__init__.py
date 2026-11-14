"""Analyzer registry. Order matters: later analyzers read ctx.shared set by earlier ones."""

from imagehunter.analyzers.binary.analyzer import BinaryStructureAnalyzer
from imagehunter.analyzers.carving.analyzer import EmbeddedSignatureAnalyzer
from imagehunter.analyzers.image.identity import ImageIdentityAnalyzer
from imagehunter.analyzers.image.animation import AnimatedImageAnalyzer
from imagehunter.analyzers.image.palette import PaletteAnalyzer
from imagehunter.analyzers.image.format_extras import ImageContainerAnalyzer
from imagehunter.analyzers.image.vision_optional import VisionOptionalAnalyzer
from imagehunter.analyzers.image.jpeg_dct import JPEGDCTAnalyzer
from imagehunter.analyzers.metadata.analyzer import MetadataAnalyzer
from imagehunter.analyzers.password_intelligence.analyzer import SmartWordsAnalyzer
from imagehunter.analyzers.decoding.analyzer import RecursiveDecodingAnalyzer
from imagehunter.analyzers.stego.analyzer import LsbFlagAnalyzer
from imagehunter.analyzers.stego.advanced import AdvancedStegoAnalyzer
from imagehunter.analyzers.text.phrases import PhraseAnalyzer
from imagehunter.analyzers.text.strings import StringsAnalyzer


def default_analyzers():
    return [ImageIdentityAnalyzer(), BinaryStructureAnalyzer(), EmbeddedSignatureAnalyzer(),
            StringsAnalyzer(), LsbFlagAnalyzer(), AdvancedStegoAnalyzer(), PhraseAnalyzer(), MetadataAnalyzer(), SmartWordsAnalyzer(), RecursiveDecodingAnalyzer(), AnimatedImageAnalyzer(), PaletteAnalyzer(), ImageContainerAnalyzer(), VisionOptionalAnalyzer(), JPEGDCTAnalyzer()]

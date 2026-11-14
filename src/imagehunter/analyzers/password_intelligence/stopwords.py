"""Small, transparent English stopword list. Stopwords are kept for clue analysis; they are only
excluded from standalone token candidates. Other languages are not bundled: stopword_language other
than 'en' is rejected by settings validation rather than silently treated as English."""

from __future__ import annotations

EN_STOPWORDS = frozenset("""
a an and are as at be been but by for from had has have he her his i in is it its of on or our
she so that the their them then there these they this to was we were what when where which who
will with you your me my do does did not no nor if into over under about after before again
""".split())

# Frequent words that are not useful as rare-word evidence, in addition to stopwords.
COMMON_WORDS = EN_STOPWORDS | frozenset("""
all any also back can come could day first get go good great just know like look make man new
now one only other out people say see some take tell think time two up use way well work year
years yes okay hello world word words
""".split())


def stopwords_for(language: str) -> frozenset[str]:
    if language != "en":
        raise ValueError(f"unsupported stopword_language {language!r}; only 'en' is bundled")
    return EN_STOPWORDS

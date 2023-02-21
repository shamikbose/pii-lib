from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult
from typing import List, Optional
import regex
import ipaddress
from presidio_analyzer.nlp_engine import NlpArtifacts


class EmailRecognizer_BigCode(PatternRecognizer):
    """
    Recognize emails using regex
    """

    PATTERNS = [
        Pattern(
            name="Email (BigCode)",
            regex=r"""
            (?<= ^ | [\b\s@,?!;:)('".\p{Han}<] )
            (
                [^\b\s@?!;,:)('"<]+
                @
                [^\b\s@!?;,/]*
                [^\b\s@?!;,/:)('">.]
                \.
                \p{L} \w{1,})
            (?= $ | [\b\s@,?!;:)('".\p{Han}>] )
            """,
            score=0.5,
        )
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[Pattern]] = None,
        supported_language: str = "en",
        supported_entity: str = "EMAIL_ADDRESS_BIG_CODE",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: NlpArtifacts = None,
        regex_flags=regex.MULTILINE | regex.VERBOSE,
    ) -> List[RecognizerResult]:
        results = []
        if self.patterns:
            pattern_result = super().analyze(
                text,
                entities=["EMAIL_ADDRESS_BIG_CODE"],
                regex_flags=regex_flags,
                nlp_artifacts=nlp_artifacts,
            )
            results.extend(pattern_result)

        return results


class IPRecognizer_BigCode(PatternRecognizer):
    """
    Recognize IP addresses using regex and validate using additional logic
    """

    PATTERNS = [
        Pattern(
            name="IPv4",
            regex=r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",
            score=0.5,
        ),
        Pattern(
            name="IPv6",
            regex=r"(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])",
            score=0.5,
        ),
    ]
    year_patterns = [
        r"(?:^|[\b\s@?,!;:\'\")(.\p{Han}])([1-2][0-9]{3}[\p{Pd}/][1-2][0-9]{3})(?:$|[\s@,?!;:\'\"(.\p{Han}])",
        r"(?:^|[\b\s@?,!;:\'\")(.\p{Han}])([1-2][0-9]{3}[\p{Pd}/.][0-3][0-9][\p{Pd}/.][0-3][0-9])(?:$|[\s@,?!;:\'\"(.\p{Han}])",
        r"(?:^|[\b\s@?,!;:\'\")(.\p{Han}])([0-3][0-9][\p{Pd}/.][0-3][0-9][\p{Pd}/.](?:[0-9]{2}|[1-2][0-9]{3}))(?:$|[\s@,?!;:\'\"(.\p{Han}])",
        r"(?:^|[\b\s@?,!;:\'\")(.\p{Han}])([0-3][0-9][\p{Pd}/](?:[0-9]{2}|[1-2][0-9]{3}))(?:$|[\s@,?!;:\'\"(.\p{Han}])",
        r"(?:^|[\b\s@?,!;:\'\")(.\p{Han}])([1-2][0-9]{3}-[0-3][0-9])(?:$|[\s@,?!;:\'\"(.\p{Han}])",
    ]
    year_regexes = [regex.compile(year_pattern) for year_pattern in year_patterns]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[Pattern]] = None,
        supported_language: str = "en",
        supported_entity: str = "IP_ADDRESS_BIG_CODE",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return (
            (self._has_digit(pattern_text))
            and not self._matches_date(pattern_text)
            and not self._not_ip_address(pattern_text)
        )

    @staticmethod
    def _has_digit(matched_str) -> bool:
        return any(map(str.isdigit, matched_str))

    @staticmethod
    def _matches_date(matched_str) -> bool:
        for year_regex in IPRecognizer_BigCode.year_regexes:
            if year_regex.match(matched_str):
                return True
        return False

    @staticmethod
    def _not_ip_address(matched_str) -> bool:
        try:
            ipaddress.ip_address(matched_str)
            return False
        except ValueError:
            return True

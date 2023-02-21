from datasets import load_dataset
from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerRegistry,
    BatchAnalyzerEngine,
    RecognizerResult,
)
from recognizers import IPRecognizer_BigCode, EmailRecognizer_BigCode

import json

ip_recognizer = IPRecognizer_BigCode()
email_recognizer = EmailRecognizer_BigCode()
registry = RecognizerRegistry()
registry.add_recognizer(ip_recognizer)
registry.add_recognizer(email_recognizer)
analyzer = AnalyzerEngine(registry=registry, supported_languages=["en"])
batch_analyzer = BatchAnalyzerEngine(analyzer_engine=analyzer)


def postprocess_secrets(result):
    """
    Postprocess the secrets found by the scan_secrets function
    """
    if result.recognizer_results:
        matches = []
        for pat_match in result.recognizer_results:
            tag = pat_match.entity_type
            start, end = pat_match.start, pat_match.end
            value = result.value[start:end]
            entity = {"tag": tag, "value": value, "start": start, "end": end}
            matches.append(entity)
        matches = json.dumps(matches)
        has_secrets = True
    else:
        matches = json.dumps([])
        has_secrets = False
    return matches, has_secrets


def analyze_dataset(examples):
    """
    Takes as input a dataset with the value in the "content" column
    """
    _list_secrets = []
    _list_has_secrets = []
    _number_secrets = []
    results_all = batch_analyzer.analyze_dict(
        {"content": examples["content"]}, language="en"
    )
    while True:
        result = next(results_all, -1)
        if result == -1:
            break
        secret_count = len(result.recognizer_results)
        matches, has_secrets = postprocess_secrets(result)
        _list_secrets.append(matches)
        _list_has_secrets.append(has_secrets)
        _number_secrets.append(secret_count)
    return {
        "secrets": _list_secrets,
        "has_secrets": _list_has_secrets,
        "number_secrets": _number_secrets,
    }

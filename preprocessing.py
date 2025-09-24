from pymorphy3 import MorphAnalyzer
import json, re, hashlib

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s)>\]"]+', text, flags=re.I)

def extract_domains(text: str) -> list[str]:
    urls = extract_urls(text)
    domains = []
    for url in urls:
        match = re.search(r'https?://([^/\s)>\]"]+)', url, flags=re.I)
        if match:
            domains.append(match.group(1).lower())
    return domains

def normalize_words(text: str) -> list[str]:
    morph = MorphAnalyzer()
    words = re.findall(r"[а-яА-ЯёЁ]+", (text or "").lower())
    return [morph.parse(w)[0].normal_form for w in words]

def file_checksum(path, algo="sha256", block_size=65536):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while chunk := f.read(block_size):
            h.update(chunk)
    return h.hexdigest()
import re, json, zipfile, os
from preprocessing import load_config, extract_urls, extract_domains, normalize_words

class PhishingDetector:
    def __init__(self):
        self.config = load_config("config.json")

        self._shorteners = self.config.get("shorteners", [])
        self._risky_exts = self.config.get("risky_exts", [])
        self._brand_domains = self.config.get("brand_domains", {})
        self.keywords_dangerous = self.config.get("keywords_dangerous", {})

        self._keywords_domains = list(self.keywords_dangerous.keys())
        self._keywords_phishing = list(
            set(kw for kws in self.keywords_dangerous.values() for kw in kws)
        )

    def exist_shorted_url(self, text: str) -> bool:
        urls = extract_urls(text)
        return any(any(short in url for short in self._shorteners) for url in urls)

    def exits_dangerous_domain(self, text: str) -> bool:
        domains = extract_domains(text)
        return any(any(danger in domain for danger in self._keywords_domains) for domain in domains)

    def exits_unencrypted_url(self, text: str) -> bool:
        return any(url.startswith("http://") for url in extract_urls(text))

    def exits_fake_domain(self, text: str) -> bool:
        domains = extract_domains(text)
        for domain in domains:
            for brand, brand_domains in self._brand_domains.items():
                if brand.lower() in domain and all(bd not in domain for bd in brand_domains):
                    return True
        return False

    def keyword_hits(self, text: str, keywords_sample: list[str]):
        words = normalize_words(text)
        count, found = 0, []
        for word in words:
            if word in keywords_sample:
                count += 1
                found.append(word)
        return round(count * 100 / len(words)) if words else 0, found

    def is_dangerous_attachment(self, attachment: str) -> bool:
        ext = '.' + attachment.split('.')[-1].lower() if '.' in attachment else ''
        return ext in self._risky_exts

    def validate_letter_format(self, data: dict) -> bool:
        required_fields = {
            "id": str,
            "datetime": str,
            "sender": str,
            "subject": str,
            "attachment": (str, type(None)),
            "text": str
        }
        for field, ftype in required_fields.items():
            if field not in data or not isinstance(data[field], ftype):
                return False
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data["sender"]):
            return False
        if not data.get("text"):
            return False
        return True

    def score_letter(self, data: dict) -> int:
        score = 0
        sender = data.get("sender", "")
        subject = data.get("subject", "")
        attachment = data.get("attachment", None)
        text = data.get("text", "")

        if self.exits_dangerous_domain(sender):
            score += 2
        subject_score, _ = self.keyword_hits(subject, self._keywords_phishing)
        if subject_score >= 20:
            score += 1
        text_score, _ = self.keyword_hits(text, self._keywords_phishing)
        if text_score >= 20:
            score += 1
        if self.exist_shorted_url(text):
            score += 1
        if self.exits_unencrypted_url(text):
            score += 1
        if self.exits_fake_domain(text):
            score += 3
        if attachment and self.is_dangerous_attachment(attachment):
            score += 2
        return score

    # ---------------------- ZIP PROCESSING ----------------------
    def classify_zip(self, zip_path: str) -> tuple[int, int, list, list]:
        ph, no_ph = 0, 0
        namesPh, namesNoPh = [], []
        with zipfile.ZipFile(zip_path, 'r') as z:
            for file_name in z.namelist():
                if file_name.startswith('__MACOSX/'):
                    continue

                try:
                    data = json.loads(z.read(file_name).decode('utf-8'))
                    if not self.validate_letter_format(data):
                        continue
                    score = self.score_letter(data)
                    if score >= 3:
                        ph += 1
                        namesPh.append(file_name)
                    else:
                        no_ph += 1
                        namesNoPh.append(file_name)
                except json.JSONDecodeError:
                    continue
                except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as e:
                    continue

        return ph, no_ph, namesPh, namesNoPh

    def classify_all_zips_in_directory(self, directory_path: str = ".") -> dict:
        results = {}
        for filename in os.listdir(directory_path):
            if filename.lower().endswith('.zip'):
                ph, no_ph, namesPh, namesNoPh = self.classify_zip(os.path.join(directory_path, filename))
                results[filename] = (ph, no_ph, namesPh, namesNoPh)

        return results


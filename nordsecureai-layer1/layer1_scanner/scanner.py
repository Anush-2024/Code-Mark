import os, re, docx
from pdfminer.high_level import extract_text
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine()

EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
CPR_RE = re.compile(r'\b\d{6}-\d{4}\b')

def scan_text(text, source):
    results = []
    presidio_results = analyzer.analyze(text=text, language='en')
    for r in presidio_results:
        results.append({
        "type": r.entity_type,
        "value": text[r.start:r.end],
        "source": source
        })

    for m in EMAIL_RE.finditer(text):
        results.append({"type": "EMAIL", "value": m.group(), "source": source})
    for m in CPR_RE.finditer(text):
        results.append({"type": "CPR", "value": m.group(), "source": source})
    return results

def scan_job(file_objs=None, folder_paths=None, sample_n=200):
    fragments = []
    if file_objs:
        for name, b in file_objs:
            text = b.decode('utf-8', errors='ignore')
            fragments.extend(scan_text(text, source=name))
    if folder_paths:
        for path in folder_paths:
            for f in os.listdir(path):
                if f.endswith(".txt"):
                    text = open(os.path.join(path, f)).read()
                elif f.endswith(".docx"):
                    text = "\n".join([p.text for p in docx.Document(os.path.join(path,f)).paragraphs])
                elif f.endswith(".pdf"):
                    text = extract_text(os.path.join(path, f))
                else:
                    continue
                fragments.extend(scan_text(text, source=f))
    return fragments

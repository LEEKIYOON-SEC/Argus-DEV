#!/usr/bin/env python3
"""배포 전 코드 문법 확인 — 화면 스크립트(JS) · 페이지 안 스크립트(HTML) · 스타일(CSS 중괄호 짝) · 파이프라인(Python).

하나라도 깨져 있으면 1 로 끝난다. 워크플로는 이 단계가 성공해야 Pages 산출물을 올리므로 깨진 파일은 배포되지 않고
직전 사이트가 그대로 남는다. JS 는 node --check 로 본다 — node 가 없으면 확인하지 못한 것이라 실패로 둔다.
파일을 고치거나 실행하지 않고 읽기만 한다(Python 은 compile 만, .pyc 를 쓰지 않는다).
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# src 가 없는 <script> 의 본문. type 이 있으면 JS 일 때만(모듈은 .mjs 로) 본다.
_INLINE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
_SRC_ATTR = re.compile(r"\bsrc\s*=", re.I)
_TYPE_ATTR = re.compile(r"\btype\s*=\s*[\"']?([^\"'\s>]+)", re.I)
_JS_TYPES = {"text/javascript", "application/javascript", "module"}


def _files(*patterns):
    out = []
    for p in patterns:
        out.extend(sorted(glob.glob(os.path.join(ROOT, p), recursive=True)))
    return out


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def check_python(path: str):
    with open(path, encoding="utf-8") as f:
        source = f.read()
    try:
        compile(source, path, "exec", dont_inherit=True)
    except SyntaxError as e:
        return f"{e.msg} ({e.lineno}행)"
    return None


def check_js(node: str, path: str):
    r = subprocess.run([node, "--check", path], capture_output=True, text=True)
    if r.returncode == 0:
        return None
    lines = [ln.strip() for ln in (r.stderr or r.stdout or "").splitlines() if ln.strip()]
    return " / ".join(lines[:4]) or f"node --check 종료 코드 {r.returncode}"


def check_inline_scripts(node: str, path: str):
    """페이지 안 스크립트 — 스크립트마다 따로 확인한다. (문제 목록, 확인한 스크립트 수)"""
    with open(path, encoding="utf-8") as f:
        html = f.read()
    problems, checked = [], 0
    for m in _INLINE.finditer(html):
        attrs, body = m.group(1), m.group(2)
        if _SRC_ATTR.search(attrs):
            continue
        kind = _TYPE_ATTR.search(attrs)
        kind = kind.group(1).lower() if kind else "text/javascript"
        if kind not in _JS_TYPES:
            continue
        fd, tmp = tempfile.mkstemp(suffix=".mjs" if kind == "module" else ".js")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as t:
                t.write(body)
            err = check_js(node, tmp)
        finally:
            os.unlink(tmp)
        checked += 1
        if err:
            problems.append(f"{_line(html, m.start(2))}행부터의 스크립트: {err}")
    return problems, checked


def check_css(path: str):
    """중괄호 짝 — 주석(/* */)과 따옴표 안은 세지 않는다. 닫는 괄호가 먼저 나오거나 끝에 남으면 깨진 것이다."""
    with open(path, encoding="utf-8") as f:
        css = f.read()
    depth, opened, i, n = 0, [], 0, len(css)
    while i < n:
        if css.startswith("/*", i):
            end = css.find("*/", i + 2)
            if end < 0:
                return f"닫히지 않은 주석 ({_line(css, i)}행)"
            i = end + 2
            continue
        c = css[i]
        if c in "\"'":
            j = i + 1
            while j < n and css[j] != c and css[j] != "\n":
                j += 2 if css[j] == "\\" else 1
            if j >= n or css[j] != c:
                return f"닫히지 않은 따옴표 ({_line(css, i)}행)"
            i = j + 1
            continue
        if c == "{":
            depth += 1
            opened.append(i)
        elif c == "}":
            depth -= 1
            if depth < 0:
                return f"여는 괄호 없는 닫는 괄호 ({_line(css, i)}행)"
            opened.pop()
        i += 1
    if depth:
        return f"닫히지 않은 중괄호 {depth}개 (마지막으로 연 곳 {_line(css, opened[-1])}행)"
    return None


def main() -> int:
    rel = lambda p: os.path.relpath(p, ROOT)  # noqa: E731
    bad = []
    py = _files("src/**/*.py")
    for path in py:
        err = check_python(path)
        if err:
            bad.append((path, err))

    js = _files("docs/js/*.js", "src/*.js")
    html = _files("docs/*.html")
    inline = 0
    node = shutil.which("node")
    if node is None:
        bad.append((os.path.join(ROOT, "docs"), "node 를 찾지 못해 JS 를 확인하지 못함"))
    else:
        for path in js:
            err = check_js(node, path)
            if err:
                bad.append((path, err))
        for path in html:
            problems, checked = check_inline_scripts(node, path)
            inline += checked
            bad.extend((path, p) for p in problems)

    css = _files("docs/css/*.css")
    for path in css:
        err = check_css(path)
        if err:
            bad.append((path, err))

    for path, err in bad:
        print(f"  ✗ {rel(path)}: {err}", flush=True)
    print(f"코드 문법 확인: Python {len(py)}개 · JS {len(js)}개 · HTML {len(html)}개(페이지 안 스크립트 {inline}개) · "
          f"CSS {len(css)}개 — {'문제 ' + str(len(bad)) + '건, 배포하지 않는다' if bad else '문제 없음'}", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

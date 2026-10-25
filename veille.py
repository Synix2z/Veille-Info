"""

Veille informatique automatisée

Usage :
    python veille.py --mode daily    # Alertes sécurité (aucun mail s'il n'y a rien de grave)
    python veille.py --mode weekly   # Résumé complet : sécurité, IA, mobile, web, actu

Secrets GitHub à définir (envoi via Gmail, le mail est envoyé à soi-même) :
    SMTP_USER       adresse Gmail (expéditeur et destinataire)
    SMTP_PASSWORD   mot de passe d'application Google
"""
from __future__ import annotations

import argparse
import html
import os
import re
import smtplib
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import NamedTuple

import feedparser
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HEADERS = {"User-Agent": "veille-bot/1.0 (+https://github.com)"}
TIMEOUT = 20          # secondes max par requête
MAX_WORKERS = 8       # nombre de flux téléchargés en parallèle

TOP_PER_CATEGORY = 5  # articles gardés par catégorie dans le digest hebdo
DAILY_THRESHOLD = 4   # score minimal pour déclencher une alerte quotidienne
DAILY_WINDOW = timedelta(hours=26)  # un peu plus de 24 h pour ne rien rater
WEEKLY_WINDOW = timedelta(days=7)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
HN_URL = "https://hn.algolia.com/api/v1/search"


class Feed(NamedTuple):
    name: str
    url: str
    bonus: int = 0  # points ajoutés au score de chaque article de cette source


SECURITY = "🔐 Sécurité"

FEEDS: dict[str, list[Feed]] = {
    SECURITY: [
        Feed("CERT-FR alertes", "https://www.cert.ssi.gouv.fr/alerte/feed/", 5),
        Feed("CERT-FR avis", "https://www.cert.ssi.gouv.fr/avis/feed/"),
        Feed("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", 1),
        Feed("BleepingComputer", "https://www.bleepingcomputer.com/feed/", 1),
        Feed("Krebs on Security", "https://krebsonsecurity.com/feed/", 1),
        Feed("Schneier on Security", "https://www.schneier.com/feed/atom/"),
        Feed("Dark Reading", "https://www.darkreading.com/rss.xml"),
        Feed("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
        Feed("Ars Technica Security", "https://arstechnica.com/security/feed/"),
        Feed("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default", 1),
        Feed("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
        Feed("ZATAZ", "https://www.zataz.com/feed/"),
        Feed("LeMagIT Sécurité", "https://www.lemagit.fr/rss/Securite.xml"),
    ],
    "🤖 IA": [
        Feed("Hugging Face", "https://huggingface.co/blog/feed.xml", 1),
        Feed("OpenAI", "https://openai.com/news/rss.xml", 1),
        Feed("Google DeepMind", "https://deepmind.google/blog/rss.xml", 1),
        Feed("Google AI", "https://blog.google/technology/ai/rss/"),
        Feed("MIT Technology Review", "https://www.technologyreview.com/topic/artificial-intelligence/feed"),
        Feed("The Verge IA", "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml"),
        Feed("Simon Willison", "https://simonwillison.net/atom/everything/"),
        Feed("ActuIA", "https://www.actuia.com/feed/"),
    ],
    "📱 Mobile": [
        Feed("Android Developers", "https://feeds.feedburner.com/blogspot/hsDu", 1),
        Feed("Apple Developer News", "https://developer.apple.com/news/rss/news.rss", 1),
        Feed("Swift.org", "https://www.swift.org/atom.xml", 1),
        Feed("React Native", "https://reactnative.dev/blog/rss.xml", 1),
        Feed("Kotlin", "https://blog.jetbrains.com/kotlin/feed/", 1),
        Feed("Flutter (releases)", "https://github.com/flutter/flutter/releases.atom"),
        Feed("9to5Mac", "https://9to5mac.com/feed/"),
        Feed("9to5Google", "https://9to5google.com/feed/"),
        Feed("Frandroid", "https://www.frandroid.com/feed"),
    ],
    "🌐 Web & dev": [
        Feed("JavaScript Weekly", "https://javascriptweekly.com/rss/", 1),
        Feed("React Status", "https://react.statuscode.com/rss/", 1),
        Feed("Node.js", "https://nodejs.org/en/feed/blog.xml", 1),
        Feed("TypeScript", "https://devblogs.microsoft.com/typescript/feed/", 1),
        Feed("Python Insider", "https://pythoninsider.blogspot.com/feeds/posts/default", 1),
        Feed("Rust Blog", "https://blog.rust-lang.org/feed.xml", 1),
        Feed("Go Blog", "https://go.dev/blog/feed.atom", 1),
        Feed("web.dev", "https://web.dev/feed.xml"),
        Feed("MDN Blog", "https://developer.mozilla.org/en-US/blog/rss.xml"),
        Feed("GitHub Blog", "https://github.blog/feed/"),
        Feed("Smashing Magazine", "https://www.smashingmagazine.com/feed/"),
        Feed("React (releases)", "https://github.com/facebook/react/releases.atom", 1),
        Feed("Vue (releases)", "https://github.com/vuejs/core/releases.atom", 1),
        Feed("Vite (releases)", "https://github.com/vitejs/vite/releases.atom"),
        Feed("Developpez.com", "https://www.developpez.com/index/rss"),
    ],
    "📰 Culture & actu tech": [
        Feed("Next", "https://next.ink/feed/", 1),
        Feed("Korben", "https://korben.info/feed", 1),
        Feed("LeMagIT", "https://www.lemagit.fr/rss/ContentSyndication.xml", 1),
        Feed("Numerama", "https://www.numerama.com/feed/"),
        Feed("Le Monde Informatique", "https://www.lemondeinformatique.fr/flux-rss/thematique/toutes-les-actualites/rss.xml"),
        Feed("Ars Technica", "https://feeds.arstechnica.com/arstechnica/index", 1),
        Feed("The Verge", "https://www.theverge.com/rss/index.xml"),
        Feed("TechCrunch", "https://techcrunch.com/feed/"),
        Feed("Lobsters", "https://lobste.rs/rss"),
    ],
}

# Expression régulière -> points. Plus le score est haut, plus l'article remonte.
KEYWORDS: dict[str, int] = {
    r"zero[- ]?day|0-day": 5,
    r"actively exploited|exploit(é|ee)e? activement|in the wild": 5,
    r"\bcritical\b|critique": 3,
    r"ransomware|\brce\b|remote code execution|supply[- ]chain|backdoor": 3,
    r"CVE-\d{4}-\d+": 2,
    r"data breach|fuite de données|leak": 2,
    r"\brelease[ds]?\b|\bv?\d+\.\d+(\.\d+)?\b|launch|lance|annonce|introduc": 1,
    r"\bnew\b|nouveau|nouvelle|open[- ]source|\bLLM\b|\bagent": 1,
}


# ---------------------------------------------------------------------------
# Récupération des articles
# ---------------------------------------------------------------------------

@dataclass
class Article:
    title: str
    link: str
    summary: str
    source: str
    score: int
    date: datetime


def clean(text: str, limit: int = 230) -> str:
    # Retire le HTML, normalise les espaces et tronque proprement
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


def score(title: str, summary: str, bonus: int) -> int:
    text = f"{title} {summary}"
    return bonus + sum(
        points for pattern, points in KEYWORDS.items()
        if re.search(pattern, text, re.IGNORECASE)
    )


def fetch_feed(feed: Feed, since: datetime) -> list[Article]:
    # Télécharge un flux RSS/Atom et renvoie ses articles parus depuis `since`
    try:
        response = requests.get(feed.url, headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
        parsed = feedparser.parse(response.content)
    except Exception as exc:  # Un flux en panne ne doit pas bloquer les autres
        print(f"[warn] {feed.name}: {exc}", file=sys.stderr)
        return []

    articles = []
    for entry in parsed.entries:
        published = entry.get("published_parsed") or entry.get("updated_parsed")
        link = entry.get("link", "")
        if not published or not link.startswith("http"):
            continue
        date = datetime(*published[:6], tzinfo=timezone.utc)
        if date < since:
            continue
        title = clean(entry.get("title", ""), 160)
        summary = clean(entry.get("summary", ""))
        articles.append(Article(
            title, link, summary, feed.name, score(title, summary, feed.bonus), date,
        ))
    return articles


def collect(feeds: list[Feed], since: datetime) -> list[Article]:
    # Récupère plusieurs flux en parallèle, retire les doublons, trie par score
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = pool.map(lambda feed: fetch_feed(feed, since), feeds)

    seen, articles = set(), []
    for batch in results:
        for article in batch:
            key = re.sub(r"\W+", "", article.title.lower())
            if key not in seen:
                seen.add(key)
                articles.append(article)
    articles.sort(key=lambda a: (a.score, a.date), reverse=True)
    return articles


def fetch_kev(days: int) -> list[Article]:
    """Failles ajoutées au catalogue CISA KEV (donc exploitées activement).

    Renvoie les failles ajoutées pendant les `days` derniers jours complets
    (aujourd'hui exclu), pour qu'une faille ne soit jamais envoyée deux fois.
    """
    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days)
    try:
        data = requests.get(KEV_URL, headers=HEADERS, timeout=TIMEOUT).json()
    except Exception as exc:
        print(f"[warn] CISA KEV: {exc}", file=sys.stderr)
        return []

    articles = []
    for vuln in data.get("vulnerabilities", []):
        added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if first_day <= added.date() < today:
            articles.append(Article(
                title=f'{vuln["cveID"]} – {vuln["vendorProject"]} {vuln["product"]}',
                link=f'https://nvd.nist.gov/vuln/detail/{vuln["cveID"]}',
                summary=clean(vuln.get("vulnerabilityName", "")),
                source="CISA KEV",
                score=99,
                date=added,
            ))
    return articles


def fetch_hacker_news(since: datetime, min_points: int = 150, limit: int = 8) -> list[Article]:
    # Posts Hacker News les plus votés
    params = {
        "tags": "story",
        "hitsPerPage": 30,
        "numericFilters": f"created_at_i>{int(since.timestamp())},points>{min_points}",
    }
    try:
        hits = requests.get(HN_URL, params=params, headers=HEADERS, timeout=TIMEOUT).json()["hits"]
    except Exception as exc:
        print(f"[warn] Hacker News: {exc}", file=sys.stderr)
        return []

    hits.sort(key=lambda h: h.get("points", 0), reverse=True)
    return [
        Article(
            title=clean(hit.get("title", ""), 160),
            link=hit.get("url") or f'https://news.ycombinator.com/item?id={hit["objectID"]}',
            summary=f'{hit.get("points", 0)} points · {hit.get("num_comments", 0)} commentaires',
            source="Hacker News",
            score=hit.get("points", 0),
            date=datetime.fromtimestamp(hit["created_at_i"], timezone.utc),
        )
        for hit in hits[:limit]
    ]


# ---------------------------------------------------------------------------
# Mise en forme et envoi du mail
# ---------------------------------------------------------------------------

BG_PAGE, BG_CARD, BG_HEADER = "#0f1420", "#161d2f", "#1d2335"
BORDER = "#2a334d"
TEXT, TEXT_SOFT, TEXT_MUTED = "#ffffff", "#b4bdd2", "#7f8aa6"
VIOLET, LILAC = "#5046e5", "#bd81fb"
GRADIENT = f"background:{VIOLET};background-image:linear-gradient(90deg,{VIOLET},{LILAC})"

FONT_TITLE = "Syne,'Space Grotesk','Segoe UI',Arial,sans-serif"
FONT_LABEL = "'Space Grotesk','Segoe UI',Arial,sans-serif"
FONT_BODY = "'DM Sans','Segoe UI',Arial,sans-serif"
FONTS_URL = (
    "https://fonts.googleapis.com/css2?family=DM+Sans:wght@400"
    "&family=Space+Grotesk:wght@500;700&family=Syne:wght@800&display=swap"
)

ACCENTS = {
    "🚨": "#dc2626", "❗": "#ea580c", "🔐": "#d97706", "🤖": "#7c3aed",
    "📱": "#059669", "🌐": "#2563eb", "📰": "#0891b2", "🔥": "#ea580c",
}
DEFAULT_ACCENT = "#475569"


def article_html(a: Article) -> str:
    summary = (
        f'<div style="margin-top:4px;font-family:{FONT_BODY};font-size:14px;'
        f'line-height:1.55;color:{TEXT_SOFT}">{html.escape(a.summary)}</div>'
        if a.summary else ""
    )
    return (
        f'<tr><td style="padding:14px 0;border-top:1px solid {BORDER}">'
        f'<a href="{html.escape(a.link)}" style="font-family:{FONT_LABEL};font-size:16px;'
        f'line-height:1.35;font-weight:500;color:{TEXT};text-decoration:none">'
        f"{html.escape(a.title)}</a>"
        f"{summary}"
        f'<div style="margin-top:6px;font-family:{FONT_LABEL};font-size:12px;font-weight:500;'
        f'color:{LILAC}">{html.escape(a.source)}'
        f" · {a.date:%d/%m}</div>"
        "</td></tr>"
    )


def section_html(heading: str, articles: list[Article]) -> str:
    # Un bloc par catégorie : titre avec sa couleur, puis la liste des articles
    accent = ACCENTS.get(heading.split()[0], DEFAULT_ACCENT)
    rows = "".join(article_html(a) for a in articles)
    return (
        '<tr><td style="padding:28px 28px 0">'
        f'<div style="border-left:4px solid {accent};padding-left:10px;'
        f"font-family:{FONT_LABEL};font-size:13px;font-weight:700;letter-spacing:.06em;"
        f'text-transform:uppercase;color:{accent}">{html.escape(heading)}</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin-top:10px">{rows}</table>'
        "</td></tr>"
    )


def render_text(sections: list[tuple[str, list[Article]]], title: str, intro: str) -> str:
    # Version texte brut, pour les messageries qui n'affichent pas le HTML
    text = [title, "=" * len(title)]
    if intro:
        text.append(intro)
    text.append("")
    for heading, articles in sections:
        text += [heading, "-" * len(heading)]
        for a in articles:
            text += [f"* {a.title} ({a.source})", f"  {a.link}"]
            if a.summary:
                text.append(f"  {a.summary}")
        text.append("")
    return "\n".join(text)


def render(sections: list[tuple[str, list[Article]]], title: str, intro: str = "") -> tuple[str, str]:
    """Construit le mail en deux versions : HTML et texte brut"""
    sections = [(heading, items) for heading, items in sections if items]
    articles = [a for _, items in sections for a in items]

    # Texte caché qui s'affiche à côté de l'objet dans la liste des mails
    preheader = html.escape(" · ".join(a.title for a in articles[:3]))
    plural = "s" if len(articles) > 1 else ""
    count = f"{len(articles)} article{plural} sélectionné{plural}"
    body = "".join(section_html(heading, items) for heading, items in sections)

    intro_html = (
        f'<div style="margin-top:10px;font-family:{FONT_BODY};font-size:14px;'
        f'line-height:1.5;color:{TEXT_SOFT}">{html.escape(intro)}</div>'
        if intro
        else ""
    )

    page = f"""<!doctype html>
    <html lang="fr">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <meta name="color-scheme" content="dark">
            <meta name="supported-color-schemes" content="dark">
            <title>{html.escape(title)}</title>
            <link href="{html.escape(FONTS_URL)}" rel="stylesheet">
        </head>
        <body style="margin:0;padding:0;background:{BG_PAGE}">
            <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">{preheader}</div>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{BG_PAGE}" style="background:{BG_PAGE}">
                <tr>
                    <td align="center" style="padding:24px 12px">
                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{BG_CARD}" style="max-width:640px;background:{BG_CARD};border:1px solid {BORDER};border-radius:12px;overflow:hidden">
                            <tr>
                                <td style="height:4px;line-height:4px;font-size:0;{GRADIENT}">&nbsp;</td>
                            </tr>
                            <tr>
                                <td style="background:{BG_HEADER};padding:28px">
                                    <div style="font-family:{FONT_TITLE};font-size:26px;line-height:1.2;font-weight:800;color:{TEXT}">{html.escape(title)}</div>
                                    {intro_html}
                                </td>
                            </tr>
                            {body}
                            <tr>
                                <td style="padding:28px;text-align:center;font-family:{FONT_BODY};font-size:12px;color:{TEXT_MUTED}">
                                    {count} · Veille Automatique
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
    </html>"""

    return page, render_text(sections, title, intro)


def send(subject: str, body_html: str, body_text: str) -> None:
    # Envoie le mail par SMTP Gmail, ou l'affiche si SMTP_USER est absent
    if not os.getenv("SMTP_USER"):
        print(f"--- {subject} ---\n{body_text}")
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ["SMTP_USER"]
    message["To"] = os.environ["SMTP_USER"]
    message.set_content(body_text)
    message.add_alternative(body_html, subtype="html")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        server.send_message(message)


# ---------------------------------------------------------------------------
# Modes d'exécution
# ---------------------------------------------------------------------------

# Titre affiché en haut du mail
TITLE_DAILY = "Veille informatique du jour"
TITLE_WEEKLY = "Veille informatique de la semaine"


def run_daily(now: datetime, today: str) -> None:
    # Alertes sécurité
    articles = collect(FEEDS[SECURITY], now - DAILY_WINDOW)
    alerts = [a for a in articles if a.score >= DAILY_THRESHOLD][:8]
    exploited = fetch_kev(days=1)

    if not alerts and not exploited:
        print("Rien de critique aujourd'hui, pas d'envoi.")
        return

    subject = f"🚨 Alertes sécurité – {today}"
    body_html, body_text = render(
        [("🚨 Exploitées activement (CISA KEV)", exploited),
         ("❗ Alertes & actus critiques", alerts)],
        TITLE_DAILY,
        "Actualités importantes aujourd'hui",
    )
    send(subject, body_html, body_text)


def run_weekly(now: datetime, today: str) -> None:
    # Récap complet de la semaine, trié par catégorie
    since = now - WEEKLY_WINDOW
    sections = [("🚨 Failles exploitées cette semaine (CISA KEV)", fetch_kev(days=7)[:8])]
    for category, feeds in FEEDS.items():
        sections.append((category, collect(feeds, since)[:TOP_PER_CATEGORY]))
    sections.append(("🔥 Hacker News – les plus votés", fetch_hacker_news(since)))

    subject = f"📰 Veille informatique – semaine du {today}"
    body_html, body_text = render(
        sections,
        TITLE_WEEKLY,
        "Sécurité, IA, mobile, web et culture générale : le tri de la semaine.",
    )
    send(subject, body_html, body_text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Veille informatique par mail")
    parser.add_argument("--mode", choices=["daily", "weekly"], required=True)
    mode = parser.parse_args().mode

    now = datetime.now(timezone.utc)
    today = now.strftime("%d/%m/%Y")
    (run_daily if mode == "daily" else run_weekly)(now, today)


if __name__ == "__main__":
    main()
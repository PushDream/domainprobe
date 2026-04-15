"""Project metadata shared across the CLI and supporting modules."""

APP_NAME = "Owusu DomainProbe"
APP_SLUG = "domainprobe"
APP_VERSION = "2.0"
APP_OWNER = "Owusu"
APP_WEBSITE = "owusuboateng.me"
APP_TAGLINE = "Operator-focused DNS, web, mail, and registrar diagnostics"
APP_SUBTITLE = "Built for support triage, incident reports, and fast domain analysis"
APP_USER_AGENT = f"{APP_SLUG}/{APP_VERSION} ({APP_OWNER})"


def app_label():
    return f"{APP_NAME} v{APP_VERSION}"

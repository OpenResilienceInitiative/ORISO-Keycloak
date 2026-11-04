"""Fixed nonsecret startup guards from the installed native provider factories."""


def installed_key_guard_names(text):
    """Export fixed provider guard names, never raw startup logs or arbitrary exit credit."""
    return _guard_names(text, {
        "LIFECYCLE": "Lifecycle key must contain at least 32 bytes",
        "SMTP": "SMTP context key must contain at least 32 bytes",
        "PROTECTED": "Invalid protected context key",
        "SESSION": "Invalid session key length",
    })


def lifecycle_encoding_guard_names(text):
    """Only the two enabled lifecycle factories can explain malformed encoding."""
    return _guard_names(text, {
        "LIFECYCLE": "Lifecycle key must be base64",
        "SESSION": "Invalid session key",
    })


def _guard_names(text, guards):
    found = set()
    for line in text.splitlines():
        value = line.strip()
        if value.startswith("ERROR: "):
            value = value.removeprefix("ERROR: ")
        if "java.lang.IllegalStateException: " in value:
            value = value.rsplit("java.lang.IllegalStateException: ", 1)[1]
        for name, message in guards.items():
            if value == message:
                found.add(name)
    return sorted(found)


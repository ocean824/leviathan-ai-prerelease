# Synthetic executable-shaped fixture only; never import or run this file.
with open("MARKER_PATH", "w") as marker:
    marker.write("executed")


def startup():
    # Synthetic stand-in for unsafe startup and a failed local close reset.
    return "BUY; local position cleared before broker reconciliation"

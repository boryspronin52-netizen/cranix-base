import re
from typing import List, Dict


class CupsAccess:
    def __init__(self, path="/etc/cups/cupsd.conf"):
        self.path = path
        self.raw = ""
        self.locations: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        with open(self.path, "r") as f:
            self.raw = f.read()
        self._parse()

    def _parse(self):
        pattern = re.compile(
            r"<Location\s+/printers/([^>]+)>(.*?)</Location>",
            re.DOTALL | re.IGNORECASE
        )

        self.locations = {}

        for match in pattern.finditer(self.raw):
            printer = match.group(1).strip()
            body = match.group(2)

            allow = re.findall(r"^\s*Allow\s+(.+)$", body, re.MULTILINE)
            deny = re.findall(r"^\s*Deny\s+(.+)$", body, re.MULTILINE)

            self.locations[printer] = {
                "allow": [a.strip() for a in allow],
                "deny": [d.strip() for d in deny],
                "raw": match.group(0)
            }

    def getAccess(self, printer: str) -> List[str]:
        if printer in self.locations:
            return self.locations[printer]["allow"]
        return []

    def setAccess(self, printer: str, allow_list: List[str]):
        block = self._build_block(printer, allow_list)

        if printer in self.locations:
            old_block = self.locations[printer]["raw"]
            self.raw = self.raw.replace(old_block, block)
        else:
            self.raw += "\n\n" + block

        self._parse()

    def _build_block(self, printer: str, allow_list: List[str]) -> str:
        lines = [f"<Location /printers/{printer}>"]
        lines.append("  Order allow,deny")

        for entry in allow_list:
            lines.append(f"  Allow {entry}")

        lines.append("  Deny all")
        lines.append("</Location>")

        return "\n".join(lines)

    def save(self):
        with open(self.path, "w") as f:
            f.write(self.raw)

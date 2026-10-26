import logging
from fastapi import Request, HTTPException

# Simple file-based audit log
logging.basicConfig(
    filename='access_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

from fastapi import HTTPException, Request

class PolicyDecisionPoint:
    """
    Role Levels:
      1 = everyone
      2 = managers
      3 = exec
      4 = admin
    """

    def __init__(self):
        self.rules = {
            "/admin": 4,
            "/exec": 3,
            "/managers": 2,
        }

    def _min_level_for_path(self, path: str) -> int:
        required = 1
        for prefix, lvl in self.rules.items():
            if path.startswith(prefix):
                required = max(required, lvl)
        return required

    def evaluate(self, user_claims: dict, request: Request) -> None:
        path = request.url.path
        user_level = int(user_claims.get("role_level", 0))
        required = self._min_level_for_path(path)

        if user_level < required:
            raise HTTPException(status_code=403, detail="Access denied by policy")
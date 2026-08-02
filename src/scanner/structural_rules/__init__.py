from scanner.structural_rules.base import StructuralRule
from scanner.structural_rules.excessive_permissions import ExcessivePermissionScopeRule
from scanner.structural_rules.missing_rate_limit_auth import MissingRateLimitOrAuthRule
from scanner.structural_rules.tool_description_injection import ToolDescriptionInjectionRule

DEFAULT_STRUCTURAL_RULES: tuple[StructuralRule, ...] = (
    ExcessivePermissionScopeRule(),
    MissingRateLimitOrAuthRule(),
    ToolDescriptionInjectionRule(),
)

__all__ = [
    "StructuralRule",
    "ExcessivePermissionScopeRule",
    "MissingRateLimitOrAuthRule",
    "ToolDescriptionInjectionRule",
    "DEFAULT_STRUCTURAL_RULES",
]

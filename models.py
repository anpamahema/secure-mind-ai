from pydantic import BaseModel, Field
from typing import Any, Literal

Role = Literal["Admin", "Security Reviewer", "Analyst", "Standard User"]
Decision = Literal["ALLOW", "BLOCK", "DENY", "REVIEW"]

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)

class SignupRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Role = "Standard User"

class InspectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=12000)
    profile: str = Field(default="Enterprise", max_length=80)
    tool_name: str | None = Field(default=None, max_length=160)
    server_name: str | None = Field(default="demo", max_length=160)
    resource_id: str | None = Field(default=None, max_length=300)
    arguments: dict[str, Any] = Field(default_factory=dict)
    transaction_amount: float | None = Field(default=None, ge=0, le=100000000)

class ApprovalDecision(BaseModel):
    action: Literal["APPROVE", "REJECT", "FALSE_POSITIVE"]
    explanation: str = Field(default="", max_length=2000)

class PolicyUpdate(BaseModel):
    block_prompt_injection: bool | None = None
    block_path_traversal: bool | None = None
    block_dangerous_commands: bool | None = None
    require_transaction_approval: bool | None = None
    transaction_threshold: float | None = Field(default=None, ge=0, le=100000000)

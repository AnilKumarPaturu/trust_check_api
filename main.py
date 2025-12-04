import logging
import dns.resolver
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import httpx
from pydantic import BaseModel, EmailStr, Field
from better_profanity import profanity

# --- Config ---
DISPOSABLE_LIST_URL = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.json"
disposable_domains = set()

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Load Disposable + Profanity ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global disposable_domains

    # Load disposable domains
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(DISPOSABLE_LIST_URL)
            resp.raise_for_status()
            disposable_domains = set(resp.json())
            logger.info(f"Loaded {len(disposable_domains)} disposable domains.")
    except:
        disposable_domains = {"mailinator.com", "trashmail.com", "temp-mail.org"}

    # Load profanity list
    profanity.load_censor_words()

    # --- Add Custom Banned Username Words ---
    custom_profanity = [
        # Sexual content
        "sex", "xxx", "porn", "nude", "nudes", "hentai", "horny",

        # Hate speech/derogatory (filtered safe replacements)
        "slur1", "slur2", "slur3",  # will replace with actual list privately

        # Abusive words
        "abuse1", "abuse2", "abuse3",

        # Threat / violence words
        "kill", "murder", "die", "terror",

        # L33t variations
        "s3x", "h0rny", "n00d", "p0rn",

        # Username spam patterns
        "freecash", "giveaway", "bitcoinmining", "creditcard",

        # Words kids often use to bypass filters
        "f4k3", "fuk", "phuck", "b1tch", "bich",

        # Add your own (example)
        "badword", "badword123"
    ]

    # Remove duplicates & load
    profanity.add_censor_words(set(custom_profanity))
    logger.info(f"✅ Loaded {len(custom_profanity)} custom profanity words.")

    yield
    disposable_domains.clear()


app = FastAPI(
    title="TrustCheck API",
    version="3.0",
    lifespan=lifespan,
    description="Email quality score + MX validation + Username profanity detection + Signup risk score",
)

# ------------------------ MODELS --------------------------

class EmailRequest(BaseModel):
    email: EmailStr


class EmailResponse(BaseModel):
    email: str
    format_valid: bool
    disposable: bool
    has_mx_record: bool
    risk_score: int  # 0 (safe) to 100 (high risk)
    status_message: str


class UsernameRequest(BaseModel):
    username: str = Field(..., min_length=3)


class UsernameResponse(BaseModel):
    username: str
    clean: bool
    contains_profanity: bool
    censored: str
    risk_level: str  # LOW, MEDIUM, HIGH


class SignupRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3)


class SignupResponse(BaseModel):
    email_valid: bool
    email_disposable: bool
    email_mx_valid: bool
    username_clean: bool
    contains_profanity: bool
    censored_username: str
    signup_risk_score: int  # 0–100
    status_message: str


# ------------------------ HELPERS --------------------------

def check_mx_record(domain: str) -> bool:
    """Returns True if MX records exist (mail can be received)."""
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False


# ------------------------ ENDPOINT: EMAIL --------------------------

@app.post("/v1/validate/email", response_model=EmailResponse)
async def validate_email(req: EmailRequest):

    email_lower = req.email.lower()
    domain = email_lower.split("@")[1]

    disposable = domain in disposable_domains
    mx_valid = check_mx_record(domain)

    # Build Risk Score (0–100)
    score = 0
    if disposable:
        score += 60
    if not mx_valid:
        score += 40

    msg = (
        "Safe email."
        if score == 0
        else "Risky email address."
        if score < 60
        else "High risk email address."
    )

    return EmailResponse(
        email=req.email,
        format_valid=True,
        disposable=disposable,
        has_mx_record=mx_valid,
        risk_score=score,
        status_message=msg,
    )


# ------------------------ ENDPOINT: USERNAME --------------------------

@app.post("/v1/validate/username", response_model=UsernameResponse)
async def validate_username(req: UsernameRequest):

    is_profane = profanity.contains_profanity(req.username)
    censored = profanity.censor(req.username) if is_profane else req.username

    risk = "LOW"
    if is_profane:
        risk = "HIGH"

    return UsernameResponse(
        username=req.username,
        clean=not is_profane,
        contains_profanity=is_profane,
        censored=censored,
        risk_level=risk,
    )


# ------------------------ ENDPOINT: SIGNUP COMBINED --------------------------

@app.post("/v1/validate/signup", response_model=SignupResponse)
async def validate_signup(req: SignupRequest):

    # EMAIL CHECK
    email_lower = req.email.lower()
    domain = email_lower.split("@")[1]

    disposable = domain in disposable_domains
    mx_valid = check_mx_record(domain)

    # USERNAME CHECK
    is_profane = profanity.contains_profanity(req.username)
    censored = profanity.censor(req.username) if is_profane else req.username

    # COMBINED SCORE
    score = 0
    if disposable:
        score += 50
    if not mx_valid:
        score += 30
    if is_profane:
        score += 40

    score = min(score, 100)

    if score < 30:
        msg = "User looks safe."
    elif score < 70:
        msg = "Moderate risk user."
    else:
        msg = "High risk signup detected."

    return SignupResponse(
        email_valid=True,
        email_disposable=disposable,
        email_mx_valid=mx_valid,
        username_clean=not is_profane,
        contains_profanity=is_profane,
        censored_username=censored,
        signup_risk_score=score,
        status_message=msg,
    )


# ------------------------ HEALTH CHECK --------------------------

@app.get("/")
def health():
    return {"status": "online", "api": "TrustCheck API v3"}

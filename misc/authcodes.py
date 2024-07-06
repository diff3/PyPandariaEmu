from enum import Enum

class AuthResult(Enum):
    WOW_SUCCESS = 0x00
    WOW_FAIL_BANNED = 0x03
    WOW_FAIL_UNKNOWN_ACCOUNT = 0x04
    WOW_FAIL_INCORRECT_PASSWORD = 0x05
    WOW_FAIL_ALREADY_ONLINE = 0x06
    WOW_FAIL_NO_TIME = 0x07
    WOW_FAIL_DB_BUSY = 0x08
    WOW_FAIL_VERSION_INVALID = 0x09
    WOW_FAIL_VERSION_UPDATE = 0x0A
    WOW_FAIL_INVALID_SERVER = 0x0B
    WOW_FAIL_SUSPENDED = 0x0C
    WOW_FAIL_FAIL_NOACCESS = 0x0D
    WOW_SUCCESS_SURVEY = 0x0E
    WOW_FAIL_PARENTCONTROL = 0x0F
    WOW_FAIL_LOCKED_ENFORCED = 0x10
    WOW_FAIL_TRIAL_ENDED = 0x11
    WOW_FAIL_OVERMIND_CONVERTED = 0x12
    WOW_FAIL_ANTI_INDULGENCE = 0x13
    WOW_FAIL_EXPIRED = 0x14
    WOW_FAIL_NO_GAME_ACCOUNT = 0x15
    WOW_FAIL_BILLING_LOCK = 0x16
    WOW_FAIL_IGR_WITHOUT_BNET = 0x17
    WOW_FAIL_AA_LOCK = 0x18
    WOW_FAIL_UNLOCKABLE_LOCK = 0x19
    WOW_FAIL_MUST_USE_BNET = 0x20
    WOW_FAIL_OTHER = 0xFF

class LoginResult(Enum):
    LOGIN_OK = 0x00
    LOGIN_INVALID_CHALLENGE_MESSAGE = 0x01
    LOGIN_SRP_ERROR = 0x02
    LOGIN_INVALID_PROOF_MESSAGE = 0x03
    LOGIN_BAD_SERVER_PROOF = 0x04
    LOGIN_INVALID_RECODE_MESSAGE = 0x05
    LOGIN_BAD_SERVER_RECODE_PROOF = 0x06
    LOGIN_UNKNOWN_ACCOUNT = 0x07
    LOGIN_UNKNOWN_ACCOUNT_PIN = 0x08
    LOGIN_UNKNOWN_ACCOUNT_CALL = 0x09
    LOGIN_INCORRECT_PASSWORD = 0x0A
    LOGIN_FAILED = 0x0B
    LOGIN_SERVER_DOWN = 0x0C
    LOGIN_BANNED = 0x0D
    LOGIN_BADVERSION = 0x0E
    LOGIN_ALREADYONLINE = 0x0F
    LOGIN_NOTIME = 0x10
    LOGIN_DBBUSY = 0x11
    LOGIN_SUSPENDED = 0x12
    LOGIN_PARENTALCONTROL = 0x13
    LOGIN_LOCKED_ENFORCED = 0x14
    LOGIN_ACCOUNT_CONVERTED = 0x15
    LOGIN_ANTI_INDULGENCE = 0x16
    LOGIN_EXPIRED = 0x17
    LOGIN_TRIAL_EXPIRED = 0x18
    LOGIN_NO_GAME_ACCOUNT = 0x19
    LOGIN_AUTH_OUTAGE = 0x1A
    LOGIN_GAME_ACCOUNT_LOCKED = 0x1B
    LOGIN_NO_BATTLENET_MANAGER = 0x1C
    LOGIN_NO_BATTLENET_APPLICATION = 0x1D
    LOGIN_MALFORMED_ACCOUNT_NAME = 0x1E
    LOGIN_USE_GRUNT = 0x1F
    LOGIN_TOO_FAST = 0x20
    LOGIN_CHARGEBACK = 0x21
    LOGIN_IGR_WITHOUT_BNET = 0x22
    LOGIN_UNLOCKABLE_LOCK = 0x23
    LOGIN_UNABLE_TO_DOWNLOAD_MODULE = 0x24
    LOGIN_NO_GAME_ACCOUNTS_IN_REGION = 0x25
    LOGIN_ACCOUNT_LOCKED = 0x26
    LOGIN_SSO_FAILED = 0x27

class ExpansionFlags(Enum):
    POST_BC_EXP_FLAG = 0x2
    PRE_BC_EXP_FLAG = 0x1
    NO_VALID_EXP_FLAG = 0x0
    
class RealmBuildInfo:
    def __init__(self, build, major_version, minor_version, bugfix_version, hotfix_version):
        self.build = build
        self.major_version = major_version
        self.minor_version = minor_version
        self.bugfix_version = bugfix_version
        self.hotfix_version = hotfix_version

PostBcAcceptedClientBuilds = [
    RealmBuildInfo(18414, 5, 4, 8, ' '),
    RealmBuildInfo(18291, 5, 4, 8, ' '),
    RealmBuildInfo(18019, 5, 4, 7, ' '),
    RealmBuildInfo(17956, 5, 4, 7, ' '),
    RealmBuildInfo(17930, 5, 4, 7, ' '),
    RealmBuildInfo(17898, 5, 4, 7, ' '),
    RealmBuildInfo(17688, 5, 4, 2, 'a'),
    RealmBuildInfo(17658, 5, 4, 2, ' '),
    RealmBuildInfo(17538, 5, 4, 1, ' '),
    RealmBuildInfo(17399, 5, 4, 0, ' '),
    RealmBuildInfo(17128, 5, 3, 0, ' '),
    RealmBuildInfo(16769, 5, 2, 0, ' '),
    RealmBuildInfo(16357, 5, 1, 0, 'a'),
    RealmBuildInfo(16309, 5, 1, 0, ' '),
    RealmBuildInfo(16135, 5, 0, 5, 'b'),
    RealmBuildInfo(15595, 4, 3, 4, ' '),
    RealmBuildInfo(14545, 4, 2, 2, ' '),
    RealmBuildInfo(13623, 4, 0, 6, 'a'),
    RealmBuildInfo(12340, 3, 3, 5, 'a'),
    RealmBuildInfo(11723, 3, 3, 3, 'a'),
    RealmBuildInfo(11403, 3, 3, 2, ' '),
    RealmBuildInfo(11159, 3, 3, 0, 'a'),
    RealmBuildInfo(10505, 3, 2, 2, 'a'),
    RealmBuildInfo(9947,  3, 1, 3, ' '),
    RealmBuildInfo(8606,  2, 4, 3, ' '),
    RealmBuildInfo(0, 0, 0, 0, ' ')  # terminator
]

PreBcAcceptedClientBuilds = [
    RealmBuildInfo(6141, 1, 12, 3, ' '),
    RealmBuildInfo(6005, 1, 12, 2, ' '),
    RealmBuildInfo(5875, 1, 12, 1, ' '),
    RealmBuildInfo(0, 0, 0, 0, ' ')  # terminator
]

def is_pre_bc_accepted_client_build(build):
    return any(info.build == build for info in PreBcAcceptedClientBuilds if info.build != 0)

def is_post_bc_accepted_client_build(build):
    return any(info.build == build for info in PostBcAcceptedClientBuilds if info.build != 0)

def is_accepted_client_build(build):
    return is_pre_bc_accepted_client_build(build) or is_post_bc_accepted_client_build(build)

def get_build_info(build):
    for info in PostBcAcceptedClientBuilds:
        if info.build == build:
            return info
    for info in PreBcAcceptedClientBuilds:
        if info.build == build:
            return info
    return None
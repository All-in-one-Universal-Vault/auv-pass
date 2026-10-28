# auv-pass copy catalog (en) — mechanism: auv-i18n crate


about-copyright = Copyright © 2026 积澍技术 (jishu.tech)
about-version = Version { $version }
attachments-placeholder = Save the entry first, then add attachments
brand-slogan = Keep dark. Stay light.

btn-add = + New
btn-allow = Allow
btn-cancel = Cancel
btn-copy = Copy
btn-create-enter = Create & Enter
btn-delete = Delete
btn-deny = Deny
btn-edit = Edit
btn-export = Export
btn-export-count = Exported { $count } entries
btn-export-kdbx = Export KDBX
btn-export-ssh-key = Export private key
btn-generate = Generate
btn-generate-ed25519 = Generate Ed25519
btn-generate-key = Generate key
btn-import = Import
btn-import-count = Imported { $count } entries
btn-import-kdbx = Import KDBX
btn-import-ssh-key = Import private key
btn-lock = Lock
btn-new = New
btn-new-vault = New vault
btn-quit = Quit
btn-restore = Restore
btn-run = Run
btn-save = Save
btn-start = Start
btn-stop = Stop
btn-unlock = Unlock

btn-ok = OK
btn-revoke = Revoke
check-dup = An entry with the same title and username already exists in this group — possible duplicate
check-url = The URL is missing an http(s):// prefix; the hyperlink may not work
check-whitespace = The password has leading/trailing spaces — make sure they are intended
editor-tab-advanced = Advanced
editor-tab-basic = Basic
empty-vault-hint = No entries yet — click "+ New" on the toolbar to add the first one
error-disk-space = Insufficient disk space: about { $need } bytes needed, { $free } available
go-back-edit = Back to Editing
dialog-import-kdbx = Import KDBX
dialog-new-entry = New entry
dialog-sign-request = Signature request
dialog-sign-request-body =  A program requests a signature with key "{ $name }" 
dialog-sign-request-key-title = Signature request for key "{ $name }"
dialog-totp-qr = TOTP QR code (scan with your phone)

empty-vault = (empty vault)

error-agent-start-failed = Failed to start agent: { $err }
error-clipboard-failed = Clipboard error: { $err }
error-entry-not-found = Entry not found
error-no-credential = ✗ Master password empty and AUV_PASS_KEYFILE unset
error-no-vault = No vault open
error-passwords-mismatch = Master passwords do not match
error-passwords-mismatch-2 = Passwords do not match.
error-path-empty = Path is empty
error-qr-generate = Failed to generate QR code
error-read-failed = Read failed: { $err }
error-required = required
error-title-required = Title is required
error-totp = TOTP failed: { $err }
error-ui = UI error: { $err }
error-unknown-subcommand = Unknown subcommand: { $name }
error-write-failed = Write failed: { $err }

expose = Expose

group-all = All
group-all-count = All ({ $count })
group-all-paren = (all)
group-favorites-count = Favorites ({ $count })
group-root = Root group
group-root-paren = (root)
group-trash-count = Trash ({ $count })

hint-empty-cancel = empty = cancel
hint-empty-generate = empty + Enter = generated
hint-enter-none = Enter = none
hint-enter-skip = Enter to skip = none
hint-enter-unused = Enter = none
hint-exclude-chars = optional blacklist, e.g. 0O1lI; Enter = none
hint-session-allowed = Allowed this session: { $count } keys (revocable)
import-preview-body = Importing { $entries } entries in { $groups } groups; skipping { $skipped }
import-preview-title = Import Preview
confirm-import = Confirm Import
msg-clipboard-cleared = Clipboard cleared
hint-group-path = '/' nests; empty = root
hint-keep-comment = empty = keep original comment
hint-keep-current = empty = keep current
hint-keep-or-clear = empty = keep; '-' = clear
hint-keyfile-any-file = Any file can be a key file; Enter = none
hint-keyfile-only = empty = key file only
hint-keyfile-only-2 = Leave empty for key-file-only
hint-no-passphrase = Leave empty if no passphrase
hint-parent-autocreate = Parent directory is created automatically
hint-password-if-keyfile = Leave empty if using a key file
hint-totp-scan = Scan with your phone authenticator to import this secret
hint-totp-secret = base32 or otpauth://; Enter = none

label-algorithm = Algorithm
label-algorithm-choices = 1=AES-256-GCM 2=ChaCha20 3=SM4-GCM (GB/T)
label-algorithm-short = Algorithm 1/2/3
label-character-set = Character set
label-charset-choices = 1=all 2=letters+digits 3=digits only
label-deriving-key = Deriving key…
label-detail-empty = Select an entry for details
label-digits-only = Digits only
label-editing = Edit: { $name }
label-entry-count = { $count } entries
label-exclude = Exclude
label-exclude-chars = Exclude chars
label-export-file-path = Export file path
label-export-master-password = Export master password
label-export-path = Export path
label-group = Group
label-groups = Groups
label-kdbx-path = KDBX file path
label-key-comment = Public-key comment and vault display name
label-key-file = Key file
label-key-file-path = Key file path
label-keyword = keyword
label-length = Length
label-letters-digits = Letters + digits
label-master-password = Master password
label-matches = Matches: { $count }
label-modified = Modified
label-name = Name
label-notes = Notes
label-passphrase = Passphrase
label-password = Password
label-password-colon = Password:
label-password-masked = ******** (c: copy, cleared in 30s)
label-path = Path
label-ssh-key-path = Private key path
label-public-key = Public key
label-repeat-master-password = Repeat master password
label-search = Search…
label-search-scope = Search (title/username/URL/notes/group)
label-title = Title
label-username = Username
label-username-colon = Username:
label-vault-file = Vault file
label-vault-password = Vault master password

attach-add-anyway = Add Anyway
attach-drop-hint = Select an entry first, then drop files
attach-large-body = File { $name } ({ $size }) exceeds 100 MB: the whole vault loads into memory, saves slow down as the vault grows, and backups get larger. Add anyway?
attach-large-title = Large File
attachments-add-file = Add File…
attachments-none = No attachments
attachments-save-as = Save As…
label-attachments = Attachments
label-current-password = Current Master Password
label-new-password = New Master Password
label-new-password-repeat = Repeat New Password
label-new-keyfile = New Key File (leave empty to keep current)
msg-password-changed = Changed; the next save re-encrypts the vault
msg-batch-trashed = { $n } entries moved to trash
msg-attachment-added = Attachment added and saved
msg-attachment-removed = Attachment removed
msg-attachment-saved = Attachment saved
login-generator-hint = Need a random password? Open the generator
msg-master-pw-generated = Generated — store it safely, then retype it in the repeat field
menu-change-password = Change Password…
menu-vault-properties = Vault Properties
menu-health-report = Health Report…
menu-font-size = Font Size
menu-dark-theme = Dark Theme
menu-light-theme = Light Theme
menu-about = About auv-pass
menu-entries = Entries
menu-entry-delete = Delete Selected Entry
menu-entry-edit = Edit Selected Entry
menu-entry-new = New Entry
menu-export-kdbx-full = Export KDBX (KDBX 4, opens in KeePassDX)
menu-file = File
menu-generator = Generator
menu-help = Help
menu-new-vault = New vault
menu-open-vault = Open vault
menu-password-generator = Password generator
menu-quit =  Quit
menu-ssh-export-full = Export SSH private key (no passphrase; keep it safe!)
menu-ssh-generate-full = Generate SSH key (Ed25519; private key never leaves the vault)
menu-ssh-import-full = Import SSH private key (OpenSSH; public key unchanged)
menu-ssh-keys = SSH Keys
menu-tools = Tools
menu-vault = Vault

msg-added-saved = Added and saved.
msg-agent-started = Agent started: { $socket }
msg-agent-started-sock = Agent started: { $socket }
  Point SSH_AUTH_SOCK to it (verify with ssh-add -l).
msg-agent-stopped = Agent stopped.
msg-allow-all = Allow all
msg-cancelled = Cancelled.
msg-configured = configured
msg-copied = Copied; auto-cleared in { $secs }s.
msg-deleted-saved = Deleted and saved.
msg-exported = Exported
msg-exported-count-path = Exported { $count } entries → { $path }.
msg-fingerprint-copied = Fingerprint copied: { $fp }
msg-generated = Generated
msg-generated-bits =  Generated: { $password } ({ $bits } bit)
msg-history-password-copied = History password copied; auto-cleared in { $secs }s.
msg-imported = Imported
msg-imported-count = Imported { $count } entries and saved.
msg-key-deleted = Key deleted.
msg-key-exposed = Exposed (available after agent restart).
msg-key-generated = Key generated and stored (hidden by default; press e to expose).
msg-key-hidden = Hidden (not exposed; effective after agent restart).
msg-locked = Locked.
msg-matched-count = Matched { $count } entries.
msg-matched-count-list = Matched { $count } entries:
msg-no-exposed-keys = No exposed keys.
msg-no-exposed-keys-hint = No exposed keys — press e to expose one first.
msg-no-totp = This entry has no TOTP configured.
msg-password-copied = Password copied; auto-cleared in { $secs }s.
msg-ssh-key-exported = Private key exported (no passphrase; keep it safe).
msg-ssh-key-imported = Private key imported (public key unchanged; no server change).
msg-public-key-copied = Public key copied (not sensitive) — paste into authorized_keys.
msg-saved = Saved.
msg-search-cleared = Search cleared.
msg-showing-results = Showing search results
msg-text = Unlocked ({ $count } entries)
msg-totp-code = TOTP code: { $code } ({ $secs }s left, keep private)
msg-unlocked-count = Unlocked ({ $count } entries).
msg-updated-history = Updated (history { $count }) and saved.
msg-username-copied = Username copied (not sensitive; not auto-cleared).
msg-vault-created = New vault created.

no-entries = (no entries)
no-matches = (no matches)

none = none

panel-confirm =  Confirm  
panel-confirm-delete =  Confirm delete 
panel-detail =  Details 
panel-entries =  Entries 
panel-groups =  Groups 
panel-history =  History: { $count } 
panel-history-snapshot =  History snapshot @{ $time } 
panel-message =  Message 
panel-search-results =  Search results ({ $count }) 
panel-select =  Select  
panel-sign-request =  Signature request 
panel-ssh-keys =  Keys (Ed25519) 
panel-ssh-keys-status =  SSH keys │ { $status }

prompt-choice-default = Select number (default 1): 
prompt-master-password = Master password (hidden): 

repeat = Repeat

status-agent-running =  agent running: { $socket } 
status-agent-stopped =  agent not running (press a to start) 
status-confirm-hintbar =  y allow │ a allow for session │ other keys deny 
status-copy-esc =  c copy  Esc back 
status-copy-hint =  (press c to copy; auto-cleared in 30s)
status-delete-hintbar =  y confirm delete │ n/Esc cancel 
status-delete-this-entry-history-included =  Delete this entry (history included)? 
status-detail-empty =  (select an entry for details)
status-detail-hintbar =  p plaintext  c copy (30s)  u copy username  t TOTP  h history  Esc back 
status-detail-meta =  History: { $count } │ TOTP: { $totp }
status-form-hintbar =  Tab/↑↓ field  Enter confirm  Esc cancel 
status-keys-hintbar =  ↑↓ select  e expose/hide  c copy public key  p copy fingerprint  x export private key  d delete  g generate  i import  a toggle agent  Esc back 
status-main-hintbar =  Tab switch pane  Enter details  n new  e edit  d delete  h history  s search  g generate  k keys  8 import  9 export  l lock  q quit 
status-no-history =  (no history) Esc back 
status-press-any-key =  press any key to return 
status-preview-hintbar =  { $totp } │ Enter full view │ c copy password │ C copy username
status-preview-modified =  { $url } │ modified { $modified }
status-title-bar =  auv-pass │ { $path } │ { $count } entries │ { $time }

tag-exposed = [exposed]
tag-exposed-short = [exposed] 
tag-hidden = [hidden]
tag-hidden-short = [hidden] 

usage-find =   find <vault> <term> [--copy]  search; --copy copies the password (cleared in 30s)
usage-list =   list <vault>             list all entries
usage-no-args =   (no args)                full-screen interactive UI
usage-slogan =   Keep dark. Stay light.
usage-version =   --version | -V           print version
health-weak = Weak Passwords (<60 bit)
health-reused = Reused Passwords
health-stale = Not Modified in >365 Days
health-ok = All checks passed
health-none = None
props-algorithm = Algorithm
props-kdf = KDF Parameters
props-entries = Entries
props-attachments = Attachments
props-file-size = File Size
props-file-sha256 = File SHA-256
props-credential = Credential
props-format = Format Version
error-old-password-wrong = Current password is incorrect
overwrite-anyway = Overwrite
overwrite-body = Target file exists: { $path }
overwrite-title = Overwrite Confirmation
save-anyway = Save Anyway
save-check-title = Pre-save Check
save-failed-title = Save Failed
status-agent-active = agent running · auto-lock paused
status-lock-countdown = auto-lock in { $time }
title-locked = Locked
toolbar-clear-clipboard = Clear Clipboard
toolbar-copy-password = Copy Password
toolbar-copy-username = Copy Username

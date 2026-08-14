<?php
declare(strict_types=1);

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use PHPMailer\PHPMailer\PHPMailer;

require __DIR__ . '/vendor/autoload.php';

$sessionLifetime = 60 * 60 * 24 * 30;
$secureSession = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
ini_set('session.gc_maxlifetime', (string) $sessionLifetime);
session_set_cookie_params([
    'lifetime' => $sessionLifetime,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => $secureSession,
]);
session_start();

const APP_NAME = 'Pastenator';
const APP_VERSION = '1.0.1';
const DB_FILE = __DIR__ . '/storage/pastenator.sqlite';
const LANGUAGES = [
    'text' => 'Plain text', 'bash' => 'Bash', 'css' => 'CSS', 'diff' => 'Diff', 'go' => 'Go',
    'html' => 'HTML', 'ini' => 'INI', 'java' => 'Java', 'javascript' => 'JavaScript',
    'json' => 'JSON', 'markdown' => 'Markdown', 'nginx' => 'Nginx', 'php' => 'PHP',
    'python' => 'Python', 'ruby' => 'Ruby', 'sql' => 'SQL', 'typescript' => 'TypeScript',
    'xml' => 'XML', 'yaml' => 'YAML',
];

main();

function main(): void
{
    $action = $_GET['a'] ?? 'home';
    if (!users_exist() && !in_array($action, ['setup', 'qr'], true)) {
        redirect('?a=setup');
    }

    match ($action) {
        'setup' => setup(),
        'register' => register(),
        'verify' => verify_email(),
        'verify-pending' => verify_pending(),
        'login' => login(),
        'twofactor-login' => twofactor_login(),
        'forgot-password' => forgot_password(),
        'reset-password' => reset_password(),
        'logout' => logout(),
        'theme' => toggle_theme(),
        'new' => paste_form(),
        'save' => save_paste(),
        'view' => view_paste(),
        'raw' => raw_paste(),
        'download' => download_paste(),
        'clone' => clone_paste(),
        'edit' => edit_paste(),
        'delete' => delete_paste(),
        'archive' => archive(),
        'mine' => mine(),
        'profile' => profile(),
        'enable-2fa' => enable_2fa(),
        'disable-2fa' => disable_2fa(),
        'qr' => qr(),
        'admin' => admin_dashboard(),
        'admin-users' => admin_users(),
        'admin-settings' => admin_settings(),
        default => home(),
    };
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    if (!is_dir(__DIR__ . '/storage')) {
        mkdir(__DIR__ . '/storage', 0775, true);
    }
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
    migrate($pdo);
    return $pdo;
}

function migrate(PDO $pdo): void
{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email_verified_at TEXT NULL,
            twofa_secret TEXT NULL,
            twofa_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pastes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            language TEXT NOT NULL DEFAULT 'text',
            visibility TEXT NOT NULL DEFAULT 'public',
            password_hash TEXT NULL,
            expires_at TEXT NULL,
            burn_after_read INTEGER NOT NULL DEFAULT 0,
            views INTEGER NOT NULL DEFAULT 0,
            tags TEXT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS trusted_2fa_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            selector TEXT NOT NULL UNIQUE,
            validator_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_used_at TEXT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_trusted_2fa_user ON trusted_2fa_tokens(user_id, expires_at);
    ");
    $defaults = [
        'allow_registration' => '1',
        'allow_guest_pastes' => '1',
        'require_email_verification' => '1',
        'site_url' => base_url(),
        'mail_from_email' => 'pastenator@quantumnet.space',
        'mail_from_name' => APP_NAME,
        'mail_transport' => 'mail',
        'mail_envelope_sender' => 'pastenator@quantumnet.space',
        'mail_reply_to' => 'mariuserbanica@proton.me',
        'smtp_host' => '',
        'smtp_port' => '587',
        'smtp_username' => '',
        'smtp_password' => '',
        'smtp_secure' => 'tls',
    ];
    $stmt = $pdo->prepare('INSERT OR IGNORE INTO settings (name, value) VALUES (?, ?)');
    foreach ($defaults as $name => $value) {
        $stmt->execute([$name, $value]);
    }
}

function users_exist(): bool
{
    return (int) db()->query('SELECT COUNT(*) FROM users')->fetchColumn() > 0;
}

function now(): string
{
    return gmdate('Y-m-d H:i:s');
}

function h(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf(): string
{
    $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}

function check_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
        flash('Your session expired. Please try again.', 'error');
        redirect($_SERVER['HTTP_REFERER'] ?? '?');
    }
}

function redirect(string $url): never
{
    header('Location: ' . $url);
    exit;
}

function toggle_theme(): void
{
    $next = ($_COOKIE['theme'] ?? '') === 'dark' ? 'light' : 'dark';
    setcookie('theme', $next, [
        'expires' => time() + 60 * 60 * 24 * 365,
        'path' => '/',
        'secure' => false,
        'httponly' => false,
        'samesite' => 'Lax',
    ]);
    redirect($_SERVER['HTTP_REFERER'] ?? '?');
}

function setting(string $name, ?string $fallback = null): string
{
    $stmt = db()->prepare('SELECT value FROM settings WHERE name = ?');
    $stmt->execute([$name]);
    $value = $stmt->fetchColumn();
    return $value === false ? (string) $fallback : (string) $value;
}

function set_setting(string $name, string $value): void
{
    $stmt = db()->prepare('INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value');
    $stmt->execute([$name, $value]);
}

function base_url(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'paste.quantumnet.space:86';
    return $scheme . '://' . $host;
}

function app_url(string $query = ''): string
{
    return rtrim(setting('site_url', base_url()), '/') . '/' . ($query !== '' ? '?' . ltrim($query, '?') : '');
}

function flash(?string $message = null, string $type = 'ok'): ?string
{
    if ($message !== null) {
        $_SESSION['flash'] = ['message' => $message, 'type' => $type];
        return null;
    }
    if (!isset($_SESSION['flash'])) {
        return null;
    }
    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return '<div class="flash ' . h($flash['type'] === 'error' ? 'error' : '') . '">' . h($flash['message']) . '</div>';
}

function current_user(): ?array
{
    if (empty($_SESSION['user_id'])) {
        return null;
    }
    $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function secure_request(): bool
{
    $forwardedProto = strtolower(trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0]));
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $forwardedProto === 'https' || str_contains((string) ($_SERVER['HTTP_CF_VISITOR'] ?? ''), '"scheme":"https"');
}

function trusted_2fa_cookie_options(int $expires): array
{
    return ['expires' => $expires, 'path' => '/', 'secure' => secure_request(), 'httponly' => true, 'samesite' => 'Lax'];
}

function clear_trusted_2fa_cookie(): void
{
    setcookie('pastenator_trusted_2fa', '', trusted_2fa_cookie_options(time() - 3600));
}

function issue_trusted_2fa_token(array $user): void
{
    $selector = bin2hex(random_bytes(9));
    $validator = bin2hex(random_bytes(32));
    $expires = time() + 60 * 60 * 24 * 21;
    db()->prepare('INSERT INTO trusted_2fa_tokens (user_id, selector, validator_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
        ->execute([(int) $user['id'], hash('sha256', $selector), hash('sha256', $validator), gmdate('Y-m-d H:i:s', $expires), now()]);
    db()->prepare('DELETE FROM trusted_2fa_tokens WHERE user_id = ? AND id NOT IN (SELECT id FROM trusted_2fa_tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 5)')
        ->execute([(int) $user['id'], (int) $user['id']]);
    setcookie('pastenator_trusted_2fa', $selector . ':' . $validator, trusted_2fa_cookie_options($expires));
}

function trusted_2fa_valid(array $user): bool
{
    $cookie = (string) ($_COOKIE['pastenator_trusted_2fa'] ?? '');
    if (!str_contains($cookie, ':')) return false;
    [$selector, $validator] = explode(':', $cookie, 2);
    if (!preg_match('/^[a-f0-9]{18}$/', $selector) || !preg_match('/^[a-f0-9]{64}$/', $validator)) return false;
    db()->prepare('DELETE FROM trusted_2fa_tokens WHERE expires_at <= ?')->execute([now()]);
    $stmt = db()->prepare('SELECT * FROM trusted_2fa_tokens WHERE selector = ? AND expires_at > ?');
    $stmt->execute([hash('sha256', $selector), now()]);
    $token = $stmt->fetch();
    if (!$token || (int) $token['user_id'] !== (int) $user['id'] || !hash_equals((string) $token['validator_hash'], hash('sha256', $validator))) {
        clear_trusted_2fa_cookie();
        return false;
    }
    db()->prepare('UPDATE trusted_2fa_tokens SET last_used_at = ? WHERE id = ?')->execute([now(), $token['id']]);
    return true;
}

function revoke_trusted_2fa_tokens(int $userId): void
{
    db()->prepare('DELETE FROM trusted_2fa_tokens WHERE user_id = ?')->execute([$userId]);
    clear_trusted_2fa_cookie();
}

function require_login(): array
{
    $user = current_user();
    if (!$user) {
        flash('Please sign in first.', 'error');
        redirect('?a=login');
    }
    return $user;
}

function require_admin(): array
{
    $user = require_login();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        exit('Forbidden.');
    }
    return $user;
}

function layout(string $title, string $content): void
{
    $user = current_user();
    $admin = $user && $user['role'] === 'admin';
    $flash = flash() ?? '';
    $theme = ($_COOKIE['theme'] ?? '') === 'dark' ? 'dark' : 'light';
    $themeLabel = $theme === 'dark' ? 'Light mode' : 'Dark mode';
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . h($title) . ' - ' . APP_NAME . '</title><link rel="icon" href="assets/logo.svg"><link rel="stylesheet" href="assets/style.css?v=20260809-mobile2"></head><body data-theme="' . h($theme) . '" data-signed-in="' . ($user ? '1' : '0') . '">';
    echo '<div class="shell"><header class="topbar"><a class="brand" href="?"><img src="assets/logo.svg" alt=""><span>' . APP_NAME . '</span></a><nav class="nav">';
    echo '<a href="?a=new">New paste</a><a href="?a=archive">Archive</a><a href="?a=theme" data-theme-toggle>' . h($themeLabel) . '</a>';
    if ($user) {
        echo '<a href="?a=mine">My pastes</a><a href="?a=profile">' . h($user['username']) . '</a>';
        if ($admin) {
            echo '<a href="?a=admin">Admin</a>';
        }
        echo '<a href="?a=logout">Sign out</a>';
    } else {
        echo '<a href="?a=login">Sign in</a>';
        if (setting('allow_registration', '1') === '1') {
            echo '<a href="?a=register">Register</a>';
        }
    }
    echo '</nav></header><main class="wrap">' . $flash . $content . '</main><footer class="footer"><div class="footer-brand"><img src="assets/logo.svg" alt=""><span>&copy; 2026 ' . APP_NAME . ' v' . APP_VERSION . '</span></div><div class="footer-links"><a href="mailto:mariuserbanica@proton.me">mariuserbanica@proton.me</a><span>&middot;</span><a href="https://mariusserbanica.co.uk/">mariusserbanica.co.uk</a></div></footer></div><script src="assets/app.js?v=20260810-update-headsup"></script></body></html>';
}

function setup(): void
{
    if (users_exist()) {
        redirect('?');
    }
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        [$username, $email, $password] = [trim($_POST['username'] ?? ''), trim($_POST['email'] ?? ''), $_POST['password'] ?? ''];
        if ($username === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 10) {
            $error = 'Use a username, a valid email, and a password of at least 10 characters.';
        } else {
            $stmt = db()->prepare('INSERT INTO users (username, email, password_hash, role, email_verified_at, created_at) VALUES (?, ?, ?, "admin", ?, ?)');
            $stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), now(), now()]);
            $_SESSION['user_id'] = (int) db()->lastInsertId();
            flash('Admin account created. Welcome to Pastenator.');
            redirect('?');
        }
    }
    $html = '<section class="panel panel-pad"><h1>Set Up Pastenator</h1><p class="muted">Create the first verified administrator account.</p>' . ($error ? '<div class="flash error">' . h($error) . '</div>' : '') . '<form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="form-row"><label>Username</label><input name="username" required></div><div class="form-row"><label>Email</label><input name="email" type="email" required></div><div class="form-row"><label>Password</label><input name="password" type="password" minlength="10" required></div><button>Create admin</button></form></section>';
    layout('Set up', $html);
}

function home(): void
{
    $pastes = public_pastes(8);
    $html = '<div class="grid two"><section class="panel panel-pad"><div class="page-title"><div><h1>Create and share code fast.</h1><p class="muted">Public, unlisted, private, expiring, passworded, and burn-after-read pastes.</p></div><a class="btn" href="?a=new">New paste</a></div>' . paste_list($pastes) . '</section><aside class="panel panel-pad"><h2>Options</h2><div class="paste-meta"><span class="pill">Syntax labels</span><span class="pill">Raw view</span><span class="pill">Downloads</span><span class="pill">Clone</span><span class="pill">Search</span><span class="pill">2FA</span><span class="pill">Admin users</span></div></aside></div>';
    layout('Home', $html);
}

function paste_form(array $paste = []): void
{
    $user = current_user();
    if (!$user && setting('allow_guest_pastes', '1') !== '1') {
        require_login();
    }
    $editing = isset($paste['id']);
    $action = $editing ? '?a=edit&p=' . h($paste['slug']) : '?a=save';
    $title = $paste['title'] ?? '';
    $content = $paste['content'] ?? '';
    $language = $paste['language'] ?? 'text';
    $visibility = $paste['visibility'] ?? 'public';
    $expires = $_POST['expires'] ?? 'never';
    $html = '<section class="panel panel-pad"><h1>' . ($editing ? 'Edit Paste' : 'New Paste') . '</h1><form method="post" action="' . $action . '" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="form-row"><label>Title</label><input name="title" value="' . h($title) . '" placeholder="Untitled paste"></div><div class="form-row"><label>Content</label><textarea id="content" class="code-entry" name="content" required>' . h($content) . '</textarea></div><div class="inline-grid"><div class="form-row"><label>Language</label><select id="language" name="language">' . language_options($language) . '</select></div><div class="form-row"><label>Visibility</label><select name="visibility">' . select_options(['public' => 'Public', 'unlisted' => 'Unlisted', 'private' => 'Private'], $visibility) . '</select></div></div><div class="inline-grid"><div class="form-row"><label>Expires</label><select name="expires">' . select_options(expiry_options(), $expires) . '</select></div><div class="form-row"><label>Optional password</label><input name="paste_password" type="password" autocomplete="new-password" placeholder="' . ($editing ? 'Leave blank to keep current password' : 'No password') . '"></div></div><div class="form-row"><label>Tags</label><input name="tags" value="' . h($paste['tags'] ?? '') . '" placeholder="php, config, snippet"></div><div class="checks"><label><input type="checkbox" name="burn_after_read" value="1" ' . (!empty($paste['burn_after_read']) ? 'checked' : '') . '> Burn after read</label><label><input type="checkbox" name="clear_password" value="1"> Remove paste password</label></div><div class="btn-row"><button>' . ($editing ? 'Save changes' : 'Create paste') . '</button><a class="btn secondary" href="?">Cancel</a></div></form></section>';
    layout($editing ? 'Edit paste' : 'New paste', $html);
}

function save_paste(): void
{
    check_csrf();
    $user = current_user();
    if (!$user && setting('allow_guest_pastes', '1') !== '1') {
        require_login();
    }
    $data = paste_payload();
    $slug = make_slug();
    $stmt = db()->prepare('INSERT INTO pastes (slug, user_id, title, content, language, visibility, password_hash, expires_at, burn_after_read, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$slug, $user['id'] ?? null, $data['title'], $data['content'], $data['language'], $data['visibility'], $data['password_hash'], $data['expires_at'], $data['burn_after_read'], $data['tags'], now(), now()]);
    flash('Paste created.');
    redirect('?a=view&p=' . urlencode($slug));
}

function edit_paste(): void
{
    check_csrf();
    $paste = find_paste($_GET['p'] ?? '');
    $user = require_login();
    authorize_owner($paste, $user);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        paste_form($paste);
        return;
    }
    $data = paste_payload($paste);
    $stmt = db()->prepare('UPDATE pastes SET title = ?, content = ?, language = ?, visibility = ?, password_hash = ?, expires_at = ?, burn_after_read = ?, tags = ?, updated_at = ? WHERE id = ?');
    $stmt->execute([$data['title'], $data['content'], $data['language'], $data['visibility'], $data['password_hash'], $data['expires_at'], $data['burn_after_read'], $data['tags'], now(), $paste['id']]);
    flash('Paste updated.');
    redirect('?a=view&p=' . urlencode($paste['slug']));
}

function paste_payload(array $existing = []): array
{
    $content = trim($_POST['content'] ?? '');
    if ($content === '') {
        flash('Paste content cannot be empty.', 'error');
        redirect($_SERVER['HTTP_REFERER'] ?? '?a=new');
    }
    $language = array_key_exists($_POST['language'] ?? '', LANGUAGES) ? $_POST['language'] : 'text';
    $visibility = in_array($_POST['visibility'] ?? 'public', ['public', 'unlisted', 'private'], true) ? $_POST['visibility'] : 'public';
    $passwordHash = $existing['password_hash'] ?? null;
    if (!empty($_POST['clear_password'])) {
        $passwordHash = null;
    } elseif (($_POST['paste_password'] ?? '') !== '') {
        $passwordHash = password_hash($_POST['paste_password'], PASSWORD_DEFAULT);
    }
    return [
        'title' => trim($_POST['title'] ?? '') ?: 'Untitled paste',
        'content' => $content,
        'language' => $language,
        'visibility' => $visibility,
        'password_hash' => $passwordHash,
        'expires_at' => expiry_to_date($_POST['expires'] ?? 'never'),
        'burn_after_read' => !empty($_POST['burn_after_read']) ? 1 : 0,
        'tags' => trim($_POST['tags'] ?? ''),
    ];
}

function view_paste(): void
{
    $paste = find_paste($_GET['p'] ?? '');
    $user = current_user();
    guard_paste_access($paste, $user);
    $authorizedOwner = $user && ($user['role'] === 'admin' || (int) $paste['user_id'] === (int) $user['id']);
    db()->prepare('UPDATE pastes SET views = views + 1 WHERE id = ?')->execute([$paste['id']]);
    $url = app_url('a=view&p=' . urlencode($paste['slug']));
    $raw = app_url('a=raw&p=' . urlencode($paste['slug']));
    $meta = '<div class="paste-meta"><span class="pill">' . h(LANGUAGES[$paste['language']] ?? $paste['language']) . '</span><span>' . h($paste['visibility']) . '</span><span>' . (int) $paste['views'] . ' views</span><span>Created ' . h($paste['created_at']) . ' UTC</span>' . ($paste['expires_at'] ? '<span>Expires ' . h($paste['expires_at']) . ' UTC</span>' : '') . (!empty($paste['burn_after_read']) ? '<span class="pill">Burn after read</span>' : '') . '</div>';
    $actions = '<div class="btn-row"><button class="secondary" data-copy="#paste-source">Copy</button><a class="btn secondary" href="?a=raw&p=' . h($paste['slug']) . '">Raw</a><a class="btn secondary" href="?a=download&p=' . h($paste['slug']) . '">Download</a><a class="btn secondary" href="?a=clone&p=' . h($paste['slug']) . '">Clone</a>' . ($authorizedOwner ? '<a class="btn secondary" href="?a=edit&p=' . h($paste['slug']) . '">Edit</a><a class="btn danger" data-confirm="Delete this paste?" href="?a=delete&p=' . h($paste['slug']) . '&csrf=' . h(csrf()) . '">Delete</a>' : '') . '</div>';
    $html = '<section class="panel panel-pad"><div class="page-title"><div><h1>' . h($paste['title']) . '</h1>' . $meta . '</div>' . $actions . '</div><div class="form-row"><label>Share URL</label><input readonly value="' . h($url) . '"></div><textarea id="paste-source" hidden>' . h($paste['content']) . '</textarea><div class="code-wrap" id="paste-code">' . render_code($paste['content']) . '</div><p class="muted">Raw URL: <a href="' . h($raw) . '">' . h($raw) . '</a></p></section>';
    if (!empty($paste['burn_after_read']) && !$authorizedOwner) {
        register_shutdown_function(static fn() => db()->prepare('DELETE FROM pastes WHERE id = ?')->execute([$paste['id']]));
    }
    layout($paste['title'], $html);
}

function raw_paste(): void
{
    $paste = find_paste($_GET['p'] ?? '');
    guard_paste_access($paste, current_user());
    db()->prepare('UPDATE pastes SET views = views + 1 WHERE id = ?')->execute([$paste['id']]);
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo $paste['content'];
    if (!empty($paste['burn_after_read'])) {
        db()->prepare('DELETE FROM pastes WHERE id = ?')->execute([$paste['id']]);
    }
}

function download_paste(): void
{
    $paste = find_paste($_GET['p'] ?? '');
    guard_paste_access($paste, current_user());
    $name = preg_replace('/[^a-z0-9._-]+/i', '-', strtolower($paste['title'])) ?: $paste['slug'];
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $name . '.txt"');
    echo $paste['content'];
}

function clone_paste(): void
{
    $paste = find_paste($_GET['p'] ?? '');
    guard_paste_access($paste, current_user());
    unset($paste['id'], $paste['slug']);
    $paste['title'] = 'Clone of ' . $paste['title'];
    paste_form($paste);
}

function delete_paste(): void
{
    if (!hash_equals($_SESSION['csrf'] ?? '', $_GET['csrf'] ?? '')) {
        http_response_code(419);
        exit('Invalid token.');
    }
    $paste = find_paste($_GET['p'] ?? '');
    $user = require_login();
    authorize_owner($paste, $user);
    db()->prepare('DELETE FROM pastes WHERE id = ?')->execute([$paste['id']]);
    flash('Paste deleted.');
    redirect('?a=mine');
}

function archive(): void
{
    $q = trim($_GET['q'] ?? '');
    if ($q !== '') {
        $stmt = db()->prepare("SELECT p.*, u.username FROM pastes p LEFT JOIN users u ON u.id = p.user_id WHERE p.visibility = 'public' AND (p.expires_at IS NULL OR p.expires_at > ?) AND (p.title LIKE ? OR p.content LIKE ? OR p.tags LIKE ?) ORDER BY p.created_at DESC LIMIT 50");
        $like = '%' . $q . '%';
        $stmt->execute([now(), $like, $like, $like]);
        $pastes = $stmt->fetchAll();
    } else {
        $pastes = public_pastes(50);
    }
    $html = '<section class="panel panel-pad"><div class="page-title"><div><h1>Public Archive</h1><p class="muted">Search public, non-expired pastes.</p></div></div><form class="btn-row" method="get"><input type="hidden" name="a" value="archive"><input name="q" value="' . h($q) . '" placeholder="Search title, content, or tags"><button>Search</button></form><br>' . paste_list($pastes) . '</section>';
    layout('Archive', $html);
}

function mine(): void
{
    $user = require_login();
    $stmt = db()->prepare('SELECT p.*, u.username FROM pastes p LEFT JOIN users u ON u.id = p.user_id WHERE p.user_id = ? ORDER BY p.created_at DESC LIMIT 100');
    $stmt->execute([$user['id']]);
    $html = '<section class="panel panel-pad"><div class="page-title"><div><h1>My Pastes</h1><p class="muted">Manage your own snippets.</p></div><a class="btn" href="?a=new">New paste</a></div>' . paste_list($stmt->fetchAll()) . '</section>';
    layout('My pastes', $html);
}

function find_paste(string $slug): array
{
    $stmt = db()->prepare('SELECT p.*, u.username FROM pastes p LEFT JOIN users u ON u.id = p.user_id WHERE p.slug = ?');
    $stmt->execute([$slug]);
    $paste = $stmt->fetch();
    if (!$paste || ($paste['expires_at'] && $paste['expires_at'] <= now())) {
        http_response_code(404);
        layout('Not found', '<section class="panel panel-pad"><h1>Paste not found</h1><p class="muted">It may have expired or been removed.</p></section>');
        exit;
    }
    return $paste;
}

function guard_paste_access(array $paste, ?array $user): void
{
    $owner = $user && ($user['role'] === 'admin' || (int) $paste['user_id'] === (int) $user['id']);
    if ($paste['visibility'] === 'private' && !$owner) {
        http_response_code(403);
        layout('Private paste', '<section class="panel panel-pad"><h1>Private paste</h1><p class="muted">Only the owner or an administrator can view this paste.</p></section>');
        exit;
    }
    if ($paste['password_hash'] && !$owner && empty($_SESSION['paste_pw_' . $paste['id']])) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            check_csrf();
            if (password_verify($_POST['paste_password'] ?? '', $paste['password_hash'])) {
                $_SESSION['paste_pw_' . $paste['id']] = true;
                redirect('?a=view&p=' . urlencode($paste['slug']));
            }
            flash('Paste password was incorrect.', 'error');
        }
        $html = '<section class="panel panel-pad"><h1>Password Required</h1><form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="form-row"><label>Paste password</label><input type="password" name="paste_password" required autofocus></div><button>Unlock paste</button></form></section>';
        layout('Unlock paste', $html);
        exit;
    }
}

function authorize_owner(array $paste, array $user): void
{
    if ($user['role'] !== 'admin' && (int) $paste['user_id'] !== (int) $user['id']) {
        http_response_code(403);
        exit('Forbidden.');
    }
}

function public_pastes(int $limit): array
{
    $stmt = db()->prepare("SELECT p.*, u.username FROM pastes p LEFT JOIN users u ON u.id = p.user_id WHERE p.visibility = 'public' AND (p.expires_at IS NULL OR p.expires_at > ?) ORDER BY p.created_at DESC LIMIT ?");
    $stmt->bindValue(1, now());
    $stmt->bindValue(2, $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function paste_list(array $pastes): string
{
    if (!$pastes) {
        return '<div class="empty">No pastes yet.</div>';
    }
    $html = '<div class="paste-list">';
    foreach ($pastes as $paste) {
        $html .= '<article class="paste-item"><h3><a href="?a=view&p=' . h($paste['slug']) . '">' . h($paste['title']) . '</a></h3><div class="paste-meta"><span class="pill">' . h(LANGUAGES[$paste['language']] ?? $paste['language']) . '</span><span>' . h($paste['username'] ?? 'Guest') . '</span><span>' . h($paste['created_at']) . ' UTC</span><span>' . (int) $paste['views'] . ' views</span>' . ($paste['tags'] ? '<span>' . h($paste['tags']) . '</span>' : '') . '</div></article>';
    }
    return $html . '</div>';
}

function render_code(string $content): string
{
    $lines = explode("\n", $content);
    $html = '<pre><table class="line-table">';
    foreach ($lines as $i => $line) {
        $html .= '<tr><td class="line-no">' . ($i + 1) . '</td><td class="line-code">' . h($line) . '</td></tr>';
    }
    return $html . '</table></pre>';
}

function language_options(string $selected): string
{
    return select_options(LANGUAGES, $selected);
}

function select_options(array $options, string $selected): string
{
    $html = '';
    foreach ($options as $value => $label) {
        $html .= '<option value="' . h((string) $value) . '" ' . ((string) $value === $selected ? 'selected' : '') . '>' . h((string) $label) . '</option>';
    }
    return $html;
}

function expiry_options(): array
{
    return ['never' => 'Never', '10m' => '10 minutes', '1h' => '1 hour', '1d' => '1 day', '1w' => '1 week', '2w' => '2 weeks', '1m' => '1 month'];
}

function expiry_to_date(string $key): ?string
{
    $map = ['10m' => '+10 minutes', '1h' => '+1 hour', '1d' => '+1 day', '1w' => '+1 week', '2w' => '+2 weeks', '1m' => '+1 month'];
    return isset($map[$key]) ? gmdate('Y-m-d H:i:s', strtotime($map[$key])) : null;
}

function make_slug(): string
{
    do {
        $slug = substr(strtr(base64_encode(random_bytes(9)), '+/', '-_'), 0, 10);
        $stmt = db()->prepare('SELECT COUNT(*) FROM pastes WHERE slug = ?');
        $stmt->execute([$slug]);
    } while ((int) $stmt->fetchColumn() > 0);
    return $slug;
}

function register(): void
{
    if (setting('allow_registration', '1') !== '1') {
        http_response_code(403);
        exit('Registration is closed.');
    }
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        if ($username === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 10) {
            $error = 'Use a username, valid email, and password of at least 10 characters.';
        } else {
            try {
                $verified = setting('require_email_verification', '1') === '1' ? null : now();
                $stmt = db()->prepare('INSERT INTO users (username, email, password_hash, role, email_verified_at, created_at) VALUES (?, ?, ?, "user", ?, ?)');
                $stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), $verified, now()]);
                $userId = (int) db()->lastInsertId();
                if ($verified === null) {
                    $_SESSION['pending_verification_email'] = $email;
                    if (send_verification($userId, $email, $username)) {
                        $_SESSION['verification_mail_message'] = 'A verification email has been sent.';
                    } else {
                        $_SESSION['verification_mail_message'] = 'Your account was created, but the mail server could not send the message. Please use resend.';
                    }
                    redirect('?a=verify-pending');
                } else {
                    flash('Account created. You can sign in now.');
                }
                redirect('?a=login');
            } catch (Throwable $e) {
                $error = 'That username or email is already registered.';
            }
        }
    }
    layout('Register', auth_form('Create Account', '?a=register', $error, true));
}

function login(): void
{
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        $stmt = db()->prepare('SELECT * FROM users WHERE email = ? OR username = ?');
        $stmt->execute([trim($_POST['login'] ?? ''), trim($_POST['login'] ?? '')]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($_POST['password'] ?? '', $user['password_hash'])) {
            $error = 'Invalid login details.';
        } elseif (!$user['email_verified_at']) {
            $_SESSION['pending_verification_email'] = $user['email'];
            redirect('?a=verify-pending');
        } elseif ((int) $user['twofa_enabled'] === 1 && !trusted_2fa_valid($user)) {
            $_SESSION['pending_2fa_user_id'] = (int) $user['id'];
            redirect('?a=twofactor-login');
        } else {
            $_SESSION['user_id'] = (int) $user['id'];
            flash('Signed in.');
            redirect('?');
        }
    }
    layout('Sign in', auth_form('Sign In', '?a=login', $error, false));
}

function auth_form(string $heading, string $action, string $error, bool $register): string
{
    $helper = $register
        ? '<p class="muted">Already registered? <a href="?a=login">Sign in</a>. Check your spam folder for emails from Pastenator.</p>'
        : '<p class="muted"><a href="?a=forgot-password">Forgot your password?</a></p>';
    return '<section class="panel panel-pad"><h1>' . h($heading) . '</h1>' . ($error ? '<div class="flash error">' . h($error) . '</div>' : '') . '<form method="post" action="' . h($action) . '" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '">' . ($register ? '<div class="form-row"><label>Username</label><input name="username" required></div><div class="form-row"><label>Email</label><input type="email" name="email" required></div>' : '<div class="form-row"><label>Email or username</label><input name="login" required></div>') . '<div class="form-row"><label>Password</label><input type="password" name="password" minlength="10" required></div><button>' . h($heading) . '</button></form>' . $helper . '</section>';
}

function forgot_password(): void
{
    if (current_user()) {
        redirect('?');
    }
    $message = '';
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        $email = strtolower(trim($_POST['email'] ?? ''));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Enter the email address on your Pastenator account.';
        } else {
            $stmt = db()->prepare('SELECT * FROM users WHERE lower(email) = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            if ($user) {
                $recent = db()->prepare('SELECT created_at FROM email_tokens WHERE user_id = ? AND purpose = "reset" ORDER BY created_at DESC LIMIT 1');
                $recent->execute([$user['id']]);
                $last = $recent->fetchColumn();
                if ($last && $last > gmdate('Y-m-d H:i:s', time() - 60)) {
                    $message = 'If that email is registered, a reset link has already been sent. Please wait one minute before trying again.';
                } else {
                    send_password_reset((int) $user['id'], $user['email'], $user['username']);
                    $message = 'If that email is registered, a password reset link has been sent. Please check your inbox and spam folder for emails from Pastenator.';
                }
            } else {
                $message = 'If that email is registered, a password reset link has been sent. Please check your inbox and spam folder for emails from Pastenator.';
            }
        }
    }
    $html = '<section class="panel panel-pad"><h1>Password Recovery</h1><p class="muted">Enter your account email and Pastenator will send a secure reset link. Remember to check your spam folder.</p>' . ($error ? '<div class="flash error">' . h($error) . '</div>' : '') . ($message ? '<div class="flash">' . h($message) . '</div>' : '') . '<form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="form-row"><label>Email address</label><input type="email" name="email" required autofocus></div><button>Send reset link</button></form><p class="muted"><a href="?a=login">Back to sign in</a></p></section>';
    layout('Password recovery', $html);
}

function send_password_reset(int $userId, string $email, string $username): bool
{
    $token = bin2hex(random_bytes(32));
    db()->prepare('DELETE FROM email_tokens WHERE user_id = ? AND purpose = "reset"')->execute([$userId]);
    db()->prepare('INSERT INTO email_tokens (user_id, token, purpose, expires_at, created_at) VALUES (?, ?, "reset", ?, ?)')->execute([$userId, hash('sha256', $token), gmdate('Y-m-d H:i:s', time() + 3600), now()]);
    $link = app_url('a=reset-password&email=' . rawurlencode($email) . '&token=' . urlencode($token));
    $subject = 'Reset your ' . APP_NAME . ' password';
    $body = '<p>Hello ' . h($username) . ',</p><p>Use this secure link to reset your Pastenator password:</p><p><a href="' . h($link) . '">' . h($link) . '</a></p><p>This link expires in 1 hour. If you did not request it, you can ignore this message.</p>';
    $text = "Hello {$username},\n\nUse this secure link to reset your Pastenator password:\n\n{$link}\n\nThis link expires in 1 hour. If you did not request it, you can ignore this message.\n\nPastenator";
    try {
        send_mail($email, $username, $subject, $body, $text);
        return true;
    } catch (Throwable $e) {
        return false;
    }
}

function reset_password(): void
{
    if (current_user()) {
        redirect('?');
    }
    $email = strtolower(trim($_GET['email'] ?? $_POST['email'] ?? ''));
    $tokenValue = (string) ($_GET['token'] ?? $_POST['token'] ?? '');
    $tokenHash = strlen($tokenValue) === 64 ? hash('sha256', $tokenValue) : '';
    $stmt = db()->prepare('SELECT t.*, u.email, u.username FROM email_tokens t JOIN users u ON u.id = t.user_id WHERE lower(u.email) = ? AND t.token = ? AND t.purpose = "reset" AND t.expires_at > ?');
    $stmt->execute([$email, $tokenHash, now()]);
    $token = $stmt->fetch();
    if (!$token) {
        flash('Password reset link is invalid or expired. Please request a new one.', 'error');
        redirect('?a=forgot-password');
    }

    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['password_confirm'] ?? '';
        if ($password !== $confirm) {
            $error = 'The new passwords do not match.';
        } elseif (strlen($password) < 10) {
            $error = 'Use a password of at least 10 characters.';
        } else {
            db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([password_hash($password, PASSWORD_DEFAULT), $token['user_id']]);
            db()->prepare('DELETE FROM email_tokens WHERE user_id = ? AND purpose = "reset"')->execute([$token['user_id']]);
            revoke_trusted_2fa_tokens((int) $token['user_id']);
            unset($_SESSION['pending_2fa_user_id']);
            flash('Password changed. You can sign in with your new password.');
            redirect('?a=login');
        }
    }

    $html = '<section class="panel panel-pad"><h1>Set New Password</h1><p class="muted">Choose a new password for <strong>' . h($email) . '</strong>.</p>' . ($error ? '<div class="flash error">' . h($error) . '</div>' : '') . '<form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><input type="hidden" name="email" value="' . h($email) . '"><input type="hidden" name="token" value="' . h($tokenValue) . '"><div class="form-row"><label>New password</label><input type="password" name="password" minlength="10" autocomplete="new-password" required autofocus></div><div class="form-row"><label>Confirm new password</label><input type="password" name="password_confirm" minlength="10" autocomplete="new-password" required></div><button>Reset password</button></form></section>';
    layout('Reset password', $html);
}

function send_verification(int $userId, string $email, string $username): bool
{
    $token = bin2hex(random_bytes(32));
    db()->prepare('DELETE FROM email_tokens WHERE user_id = ? AND purpose = "verify"')->execute([$userId]);
    db()->prepare('INSERT INTO email_tokens (user_id, token, purpose, expires_at, created_at) VALUES (?, ?, "verify", ?, ?)')->execute([$userId, hash('sha256', $token), gmdate('Y-m-d H:i:s', time() + 86400), now()]);
    $link = app_url('a=verify&email=' . rawurlencode($email) . '&token=' . urlencode($token));
    $subject = 'Confirm your ' . APP_NAME . ' email';
    $body = '<p>Hello ' . h($username) . ',</p><p>Confirm your email address to activate your Pastenator account:</p><p><a href="' . h($link) . '">' . h($link) . '</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this message.</p>';
    $text = "Hello {$username},\n\nConfirm your email address to activate your Pastenator account:\n\n{$link}\n\nThis link expires in 24 hours. If you did not create this account, you can ignore this message.\n\nPastenator";
    try {
        send_mail($email, $username, $subject, $body, $text);
        return true;
    } catch (Throwable $e) {
        return false;
    }
}

function verify_email(): void
{
    $email = strtolower(trim($_GET['email'] ?? ''));
    $tokenValue = (string) ($_GET['token'] ?? '');
    $stmt = db()->prepare('SELECT t.*, u.email FROM email_tokens t JOIN users u ON u.id = t.user_id WHERE u.email = ? AND t.token = ? AND t.purpose = "verify" AND t.expires_at > ?');
    $stmt->execute([$email, strlen($tokenValue) === 64 ? hash('sha256', $tokenValue) : '', now()]);
    $token = $stmt->fetch();
    if (!$token) {
        flash('Verification link is invalid or expired.', 'error');
        redirect('?a=login');
    }
    db()->prepare('UPDATE users SET email_verified_at = ? WHERE id = ?')->execute([now(), $token['user_id']]);
    db()->prepare('DELETE FROM email_tokens WHERE user_id = ? AND purpose = "verify"')->execute([$token['user_id']]);
    $_SESSION['user_id'] = (int) $token['user_id'];
    unset($_SESSION['pending_verification_email'], $_SESSION['verification_mail_message']);
    flash('Email confirmed. Your account is ready.');
    redirect('?');
}

function verify_pending(): void
{
    $email = (string) ($_SESSION['pending_verification_email'] ?? '');
    if ($email === '') {
        redirect('?a=login');
    }
    $message = (string) ($_SESSION['verification_mail_message'] ?? '');
    unset($_SESSION['verification_mail_message']);
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        $stmt = db()->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if (!$user) {
            unset($_SESSION['pending_verification_email']);
            redirect('?a=register');
        }
        if ($user['email_verified_at']) {
            redirect('?a=login');
        }
        $recent = db()->prepare('SELECT created_at FROM email_tokens WHERE user_id = ? AND purpose = "verify" ORDER BY created_at DESC LIMIT 1');
        $recent->execute([$user['id']]);
        $last = $recent->fetchColumn();
        if ($last && $last > gmdate('Y-m-d H:i:s', time() - 60)) {
            $message = 'Please wait one minute before requesting another email.';
        } else {
            $sent = send_verification((int) $user['id'], $user['email'], $user['username']);
            $message = $sent ? 'A new verification email has been sent.' : 'The mail server could not send the message. Please try again shortly.';
        }
    }
    $html = '<section class="panel panel-pad"><h1>Confirm Your Email</h1><p class="muted">We sent a verification link to <strong>' . h($email) . '</strong>. It expires in 24 hours.</p>' . ($message ? '<div class="flash">' . h($message) . '</div>' : '') . '<form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><button class="secondary">Resend verification email</button></form><p class="muted"><a href="?a=login">Back to sign in</a></p></section>';
    layout('Confirm email', $html);
}

function send_mail(string $email, string $name, string $subject, string $html, string $text): void
{
    if (setting('mail_transport', 'mail') === 'mail' || setting('smtp_host') === '') {
        $headers = [
            'From: ' . setting('mail_from_name', APP_NAME) . ' <' . setting('mail_from_email', 'pastenator@quantumnet.space') . '>',
            'Reply-To: ' . setting('mail_reply_to', 'mariuserbanica@proton.me'),
            'Content-Type: text/plain; charset=UTF-8',
            'X-Mailer: ' . APP_NAME,
        ];
        $envelope = setting('mail_envelope_sender', 'pastenator@quantumnet.space');
        if (!@mail($email, $subject, $text, implode("\r\n", $headers), '-f' . $envelope)) {
            throw new RuntimeException('Mail server rejected the message.');
        }
        return;
    }

    $mail = new PHPMailer(true);
    $mail->CharSet = 'UTF-8';
    if (setting('smtp_host') !== '') {
        $mail->isSMTP();
        $mail->Host = setting('smtp_host');
        $mail->Port = (int) setting('smtp_port', '587');
        $mail->SMTPAuth = setting('smtp_username') !== '';
        $mail->Username = setting('smtp_username');
        $mail->Password = setting('smtp_password');
        $secure = setting('smtp_secure', 'tls');
        if ($secure !== 'none') {
            $mail->SMTPSecure = $secure;
        }
    }
    $mail->setFrom(setting('mail_from_email'), setting('mail_from_name', APP_NAME));
    if (setting('mail_reply_to') !== '') {
        $mail->addReplyTo(setting('mail_reply_to'));
    }
    $mail->addAddress($email, $name);
    $mail->Subject = $subject;
    $mail->isHTML(true);
    $mail->Body = $html;
    $mail->AltBody = $text;
    $mail->send();
}

function twofactor_login(): void
{
    if (empty($_SESSION['pending_2fa_user_id'])) {
        redirect('?a=login');
    }
    $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['pending_2fa_user_id']]);
    $user = $stmt->fetch();
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        if ($user && verify_totp($user['twofa_secret'], $_POST['code'] ?? '')) {
            $_SESSION['user_id'] = (int) $user['id'];
            unset($_SESSION['pending_2fa_user_id']);
            issue_trusted_2fa_token($user);
            flash('Signed in.');
            redirect('?');
        }
        $error = 'Invalid authentication code.';
    }
    $html = '<section class="panel panel-pad"><h1>Two-Factor Authentication</h1>' . ($error ? '<div class="flash error">' . h($error) . '</div>' : '') . '<form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="form-row"><label>6-digit code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus></div><button>Verify</button></form></section>';
    layout('2FA', $html);
}

function logout(): void
{
    setcookie(session_name(), '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_destroy();
    session_start();
    flash('Signed out.');
    redirect('?');
}

function profile(): void
{
    $user = require_login();
    $twofa = (int) $user['twofa_enabled'] === 1 ? '<span class="pill">Enabled</span><form method="post" action="?a=disable-2fa" class="btn-row"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><button class="danger">Disable 2FA</button></form>' : '<span class="pill">Disabled</span><a class="btn" href="?a=enable-2fa">Enable 2FA</a>';
    $html = '<section class="panel panel-pad"><h1>Profile</h1><p class="muted">' . h($user['email']) . '</p><h2>Two-Factor Authentication</h2><div class="btn-row">' . $twofa . '</div></section>';
    layout('Profile', $html);
}

function enable_2fa(): void
{
    $user = require_login();
    $secret = $_SESSION['new_2fa_secret'] ??= base32_secret();
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        if (verify_totp($secret, $_POST['code'] ?? '')) {
            db()->prepare('UPDATE users SET twofa_secret = ?, twofa_enabled = 1 WHERE id = ?')->execute([$secret, $user['id']]);
            unset($_SESSION['new_2fa_secret']);
            flash('Two-factor authentication enabled.');
            redirect('?a=profile');
        }
        $error = 'Invalid code. Scan the QR code and try again.';
    }
    $otpauth = otpauth_url($user['email'], $secret);
    $html = '<section class="panel panel-pad"><h1>Enable 2FA</h1>' . ($error ? '<div class="flash error">' . h($error) . '</div>' : '') . '<p class="muted">Scan this QR code in your authenticator app, then enter the 6-digit code.</p><img class="qr" src="?a=qr&data=' . urlencode($otpauth) . '" alt="2FA QR code"><form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="form-row"><label>Authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" required></div><button>Enable 2FA</button></form><p class="muted">Manual secret: <code>' . h($secret) . '</code></p></section>';
    layout('Enable 2FA', $html);
}

function disable_2fa(): void
{
    check_csrf();
    $user = require_login();
    db()->prepare('UPDATE users SET twofa_secret = NULL, twofa_enabled = 0 WHERE id = ?')->execute([$user['id']]);
    revoke_trusted_2fa_tokens((int) $user['id']);
    flash('Two-factor authentication disabled.');
    redirect('?a=profile');
}

function qr(): void
{
    $data = $_GET['data'] ?? '';
    if ($data === '') {
        http_response_code(400);
        exit;
    }
    $renderer = new ImageRenderer(new RendererStyle(260), new SvgImageBackEnd());
    header('Content-Type: image/svg+xml');
    echo (new Writer($renderer))->writeString($data);
}

function base32_secret(int $length = 32): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $secret;
}

function base32_decode_secret(string $secret): string
{
    $secret = strtoupper(preg_replace('/[^A-Z2-7]/', '', $secret));
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($secret) as $char) {
        $bits .= str_pad(decbin(strpos($alphabet, $char)), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) {
            $bytes .= chr(bindec($chunk));
        }
    }
    return $bytes;
}

function totp(string $secret, ?int $slice = null): string
{
    $slice ??= (int) floor(time() / 30);
    $counter = pack('N*', 0, $slice);
    $hash = hash_hmac('sha1', $counter, base32_decode_secret($secret), true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $part = substr($hash, $offset, 4);
    $value = unpack('N', $part)[1] & 0x7FFFFFFF;
    return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
}

function verify_totp(?string $secret, string $code): bool
{
    if (!$secret) {
        return false;
    }
    $code = preg_replace('/\D/', '', $code);
    $slice = (int) floor(time() / 30);
    foreach ([-1, 0, 1] as $window) {
        if (hash_equals(totp($secret, $slice + $window), $code)) {
            return true;
        }
    }
    return false;
}

function otpauth_url(string $label, string $secret): string
{
    return 'otpauth://totp/' . rawurlencode(APP_NAME . ':' . $label) . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode(APP_NAME) . '&algorithm=SHA1&digits=6&period=30';
}

function admin_dashboard(): void
{
    require_admin();
    $counts = [
        'users' => db()->query('SELECT COUNT(*) FROM users')->fetchColumn(),
        'pastes' => db()->query('SELECT COUNT(*) FROM pastes')->fetchColumn(),
        'public' => db()->query("SELECT COUNT(*) FROM pastes WHERE visibility = 'public'")->fetchColumn(),
    ];
    $html = '<section class="panel panel-pad"><h1>Admin</h1><div class="paste-meta"><span class="pill">' . (int) $counts['users'] . ' users</span><span class="pill">' . (int) $counts['pastes'] . ' pastes</span><span class="pill">' . (int) $counts['public'] . ' public</span></div><br><div class="btn-row"><a class="btn" href="?a=admin-users">Users</a><a class="btn secondary" href="?a=admin-settings">Settings</a></div></section>';
    layout('Admin', $html);
}

function admin_users(): void
{
    require_admin();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        $id = (int) ($_POST['id'] ?? 0);
        if (isset($_POST['role'])) {
            db()->prepare('UPDATE users SET role = ? WHERE id = ?')->execute([$_POST['role'] === 'admin' ? 'admin' : 'user', $id]);
        }
        if (isset($_POST['verify'])) {
            db()->prepare('UPDATE users SET email_verified_at = ? WHERE id = ?')->execute([now(), $id]);
        }
        flash('User updated.');
        redirect('?a=admin-users');
    }
    $users = db()->query('SELECT * FROM users ORDER BY created_at DESC')->fetchAll();
    $html = '<section class="panel panel-pad"><h1>Users</h1><table class="table"><tr><th>User</th><th>Email</th><th>Role</th><th>Verified</th><th>2FA</th><th></th></tr>';
    foreach ($users as $u) {
        $html .= '<tr><td>' . h($u['username']) . '</td><td>' . h($u['email']) . '</td><td>' . h($u['role']) . '</td><td>' . ($u['email_verified_at'] ? 'Yes' : 'No') . '</td><td>' . ((int) $u['twofa_enabled'] === 1 ? 'Yes' : 'No') . '</td><td><form method="post" class="btn-row"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><input type="hidden" name="id" value="' . (int) $u['id'] . '"><select name="role">' . select_options(['user' => 'User', 'admin' => 'Admin'], $u['role']) . '</select><button class="secondary">Role</button>' . (!$u['email_verified_at'] ? '<button name="verify" value="1">Verify</button>' : '') . '</form></td></tr>';
    }
    $html .= '</table></section>';
    layout('Users', $html);
}

function admin_settings(): void
{
    require_admin();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_csrf();
        foreach (['allow_registration', 'allow_guest_pastes', 'require_email_verification'] as $bool) {
            set_setting($bool, !empty($_POST[$bool]) ? '1' : '0');
        }
        foreach (['site_url', 'mail_from_email', 'mail_from_name', 'mail_transport', 'mail_envelope_sender', 'mail_reply_to', 'smtp_host', 'smtp_port', 'smtp_username', 'smtp_secure'] as $name) {
            set_setting($name, trim($_POST[$name] ?? ''));
        }
        if (($_POST['smtp_password'] ?? '') !== '') {
            set_setting('smtp_password', $_POST['smtp_password']);
        }
        flash('Settings saved.');
        redirect('?a=admin-settings');
    }
    $html = '<section class="panel panel-pad"><h1>Settings</h1><form method="post" class="form-grid"><input type="hidden" name="csrf" value="' . h(csrf()) . '"><div class="checks"><label><input type="checkbox" name="allow_registration" value="1" ' . (setting('allow_registration') === '1' ? 'checked' : '') . '> Allow registration</label><label><input type="checkbox" name="allow_guest_pastes" value="1" ' . (setting('allow_guest_pastes') === '1' ? 'checked' : '') . '> Allow guest pastes</label><label><input type="checkbox" name="require_email_verification" value="1" ' . (setting('require_email_verification') === '1' ? 'checked' : '') . '> Require email confirmation</label></div><div class="form-row"><label>Site URL</label><input name="site_url" value="' . h(setting('site_url')) . '"></div><div class="inline-grid"><div class="form-row"><label>Mail transport</label><select name="mail_transport">' . select_options(['mail' => 'Local mail', 'smtp' => 'SMTP'], setting('mail_transport', 'mail')) . '</select></div><div class="form-row"><label>Envelope sender</label><input name="mail_envelope_sender" value="' . h(setting('mail_envelope_sender', 'pastenator@quantumnet.space')) . '"></div></div><div class="inline-grid"><div class="form-row"><label>From email</label><input name="mail_from_email" value="' . h(setting('mail_from_email')) . '"></div><div class="form-row"><label>From name</label><input name="mail_from_name" value="' . h(setting('mail_from_name')) . '"></div></div><div class="form-row"><label>Reply-to email</label><input name="mail_reply_to" value="' . h(setting('mail_reply_to', 'mariuserbanica@proton.me')) . '"></div><div class="inline-grid"><div class="form-row"><label>SMTP host</label><input name="smtp_host" value="' . h(setting('smtp_host')) . '"></div><div class="form-row"><label>SMTP port</label><input name="smtp_port" value="' . h(setting('smtp_port')) . '"></div></div><div class="inline-grid"><div class="form-row"><label>SMTP username</label><input name="smtp_username" value="' . h(setting('smtp_username')) . '"></div><div class="form-row"><label>SMTP password</label><input name="smtp_password" type="password" placeholder="Leave blank to keep current"></div></div><div class="form-row"><label>SMTP security</label><select name="smtp_secure">' . select_options(['tls' => 'TLS', 'ssl' => 'SSL', 'none' => 'None'], setting('smtp_secure', 'tls')) . '</select></div><button>Save settings</button></form></section>';
    layout('Settings', $html);
}

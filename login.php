<?php
/**
 * Login Page (login.php)
 * Traditional PHP login page with Remember Me
 */

session_start();
require_once __DIR__ . '/backend/config/session.php';

// Check if already logged in
if (isLoggedIn()) {
    $user = getCurrentUser();
    if ($user['role'] === 'admin') {
        header('Location: admin.php');
    } else {
        header('Location: dashboard.php');
    }
    exit();
}

// Check remember me cookie
checkRememberMeCookie();

$error = '';
$success = '';

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    require_once __DIR__ . '/backend/config/database.php';
    require_once __DIR__ . '/backend/config/auth.php';
    
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $rememberMe = isset($_POST['remember_me']);
    
    if (empty($username) || empty($password)) {
        $error = 'Username and password are required';
    } else {
        $database = new Database();
        $db = $database->getConnection();
        
        try {
            $stmt = $db->prepare("SELECT id, username, email, password, role FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            if ($user && verifyPassword($password, $user['password'])) {
                // Initialize session
                initUserSession([
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ]);
                
                // Set remember me cookie
                if ($rememberMe) {
                    setRememberMeCookie($user['id'], $user['username']);
                }
                
                // Redirect based on role
                if ($user['role'] === 'admin') {
                    header('Location: admin.php');
                } else {
                    header('Location: dashboard.php');
                }
                exit();
            } else {
                $error = 'Invalid username or password';
            }
        } catch(PDOException $e) {
            $error = 'Database error occurred';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Citizen System</title>
    <link rel="stylesheet" href="frontend/src/App.css">
    <link rel="stylesheet" href="frontend/src/pages/Auth.css">
</head>
<body>
    <div class="auth-page">
        <div class="auth-container">
            <div class="auth-card">
                <div class="auth-header">
                    <h1>Login</h1>
                    <p>Welcome back to Citizen System</p>
                </div>

                <?php if ($error): ?>
                    <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
                <?php endif; ?>

                <form method="POST" action="login.php">
                    <div class="form-group">
                        <label class="form-label" for="username">Username or Email</label>
                        <input
                            type="text"
                            name="username"
                            id="username"
                            class="form-input"
                            placeholder="Enter your username or email"
                            required
                            value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                        />
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input
                            type="password"
                            name="password"
                            id="password"
                            class="form-input"
                            placeholder="Enter your password"
                            required
                        />
                    </div>

                    <div class="form-group">
                        <label style="display: flex; align-items: center; cursor: pointer;">
                            <input
                                type="checkbox"
                                name="remember_me"
                                id="remember_me"
                                style="margin-right: 8px;"
                            />
                            <span>Remember Me</span>
                        </label>
                    </div>

                    <button type="submit" name="login" class="btn btn-primary btn-block">
                        Login
                    </button>
                </form>

                <div class="auth-footer">
                    <p>
                        Don't have an account? <a href="register.php">Register here</a>
                    </p>
                    <p>
                        <a href="index.php">Back to Home</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>


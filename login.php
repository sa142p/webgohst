<?php
// Start session
session_start();

// Database connection
$servername = "localhost"; // Database server
$username = "root"; // Database username
$password = ""; // Database password
$dbname = "user_database"; // Database name

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle POST request for Login or Signup
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Handle login
    if (isset($_POST['login'])) {
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            die("Error preparing statement: " . $conn->error);
        }
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Set session variables for logged-in user
                $_SESSION['loggedin'] = true;
                $_SESSION['user_id'] = $user['id']; // Assuming 'id' is the primary key
                $_SESSION['email'] = $user['email'];
                $_SESSION['name'] = $user['name']; // Store user name in session

                // Redirect to the index page
                header("Location: index.php");
                exit;
            } else {
                $error_message = "Invalid password.";
            }
        } else {
            $error_message = "No user found with this email.";
        }
    }

    // Handle signup
    if (isset($_POST['signup'])) {
        $name = $_POST['name']; // Capture the name field
        $confirm_password = $_POST['confirm_password'];
        if ($password === $confirm_password) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Check if email is already registered
            $sql = "SELECT * FROM users WHERE email = ?";
            $stmt = $conn->prepare($sql);
            if (!$stmt) {
                die("Error preparing statement: " . $conn->error);
            }
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 0) {
                // Handle profile picture upload
                $profile_picture = '';
                if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === 0) {
                    $target_dir = "uploads/";
                    $target_file = $target_dir . basename($_FILES["profile_picture"]["name"]);
                    if (move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $target_file)) {
                        $profile_picture = $target_file;
                    } else {
                        $error_message = "Error uploading profile picture.";
                        exit;
                    }
                }

                // Insert new user into the database
                $sql = "INSERT INTO users (name, email, password, profile_picture) VALUES (?, ?, ?, ?)";
                $stmt = $conn->prepare($sql);
                if (!$stmt) {
                    die("Error preparing statement: " . $conn->error);
                }
                $stmt->bind_param("ssss", $name, $email, $hashed_password, $profile_picture);

                if ($stmt->execute()) {
                    // Set session variables for logged-in user
                    $_SESSION['loggedin'] = true;
                    $_SESSION['user_id'] = $stmt->insert_id;
                    $_SESSION['email'] = $email;
                    $_SESSION['name'] = $name;

                    // Redirect to the index page
                    header("Location: index.php");
                    exit;
                } else {
                    $error_message = "Error: " . $stmt->error;
                }
            } else {
                $error_message = "Email is already registered.";
            }
        } else {
            $error_message = "Passwords do not match.";
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login & Signup</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="wrapper">
    <div class="title-text">
        <div class="title login">Login Form</div>
        <div class="title signup">Signup Form</div>
    </div>
    <div class="form-container">
        <div class="slide-controls">
            <input type="radio" name="slide" id="login" checked>
            <input type="radio" name="slide" id="signup">
            <label for="login" class="slide login">Login</label>
            <label for="signup" class="slide signup">Signup</label>
            <div class="slider-tab"></div>
        </div>
        <div class="form-inner">
            <!-- Login Form -->
            <form action="login.php" method="POST" class="login">
                <div class="field">
                    <input type="text" name="email" placeholder="Email Address" required>
                </div>
                <div class="field">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <div class="pass-link"><a href="#">Forgot password?</a></div>
                <div class="field btn">
                    <div class="btn-layer"></div>
                    <input type="submit" name="login" value="Login">
                </div>
                <div class="signup-link">Not a member? <a href="#">Signup now</a></div>
            </form>

            <!-- Signup Form -->
            <form action="login.php" method="POST" class="signup" enctype="multipart/form-data">
                <div class="field">
                    <input type="text" name="email" placeholder="Email Address" required>
                </div>
                <div class="field">
                    <input type="text" name="name" placeholder="Your Name" required>
                </div>
                <div class="field">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <div class="field">
                    <input type="password" name="confirm_password" placeholder="Confirm Password" required>
                </div>
                <div class="field">
                    <input type="file" name="profile_picture" accept="image/*">
                </div>
                <div class="field btn">
                    <div class="btn-layer"></div>
                    <input type="submit" name="signup" value="Signup">
                </div>
            </form>
        </div>
    </div>
</div>

<?php if (isset($error_message)): ?>
    <div class="error-message">
        <p><?php echo $error_message; ?></p>
    </div>
<?php endif; ?>

<script src="script.js"></script>
</body>
</html>

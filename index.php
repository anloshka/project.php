<?php
header('Content-Type: application/json');

// Включаем файл конфигурации для подключения к базе данных
include('config.php');

// Включаем файл для обработки аутентификации и токенов
include('auth_handler.php'); // Обратите внимание на этот файл

$request_uri = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
$request_method = $_SERVER['REQUEST_METHOD'];

if ($request_method === 'POST' && $request_uri === '/project/api/login') {
    handleLoginRequest($conn); // Эти функции перенесены в auth_handler.php
} elseif ($request_method === 'POST' && $request_uri === '/project/api/refresh-token') {
    handleRefreshTokenRequest(); // Эти функции перенесены в auth_handler.php
} else {
    // Проверка JWT-токена для защищенных маршрутов
    $token = validateToken(); // Эта функция перенесена в auth_handler.php
    if ($newToken = refreshToken($token)) { // Эта функция перенесена в auth_handler.php
        header('Authorization: Bearer ' . $newToken);
    }
    handleRequest($request_method, $request_uri, $conn, $token);
}

function handleRequest($method, $uri, $conn, $token) {
    if ($method === 'GET' && $uri === '/project/api/greeting') {
        handleGetRequest($conn, $token);
    } elseif ($method === 'POST' && $uri === '/project/api/greeting') {
        handlePostRequest($conn);
    } elseif ($method === 'PUT' && $uri === '/project/api/greeting') {
        handlePutRequest($conn);
    } elseif ($method === 'DELETE' && $uri === '/project/api/greeting') {
        handleDeleteRequest($conn);
    } else {
        handleNotFound($uri);
    }
}

function handleGetRequest($conn, $token) {
    // Извлечение username из токена
    $username = $token->claims()->get('username');

    // Запрос к базе данных для получения информации о пользователе
    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    $response = array();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $response = array(
            "id" => $user['id'],
            "username" => $user['username'],
            "password" => $user['password'],
            "status" => "success"
        );
    } else {
        $response = array(
            "message" => "User not found",
            "status" => "error"
        );
    }

    echo json_encode($response);
}

function handlePostRequest($conn) {
    $input = json_decode(file_get_contents('php://input'), true);

    // Проверка наличия ключей "username" и "password" и их значений
    if (!isset($input['username']) || trim($input['username']) === '' || !isset($input['password']) || trim($input['password']) === '') {
        $response = array(
            "message" => "Username and password cannot be empty",
            "status" => "error"
        );
        echo json_encode($response);
        return;
    }

    $username = trim($input['username']);  // Убираем пробелы из начала и конца
    $password = trim($input['password']);  // Убираем пробелы из начала и конца

    // Проверка на уникальность имени пользователя
    $sql = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $response = array(
            "message" => "Username already exists",
            "status" => "error"
        );
        echo json_encode($response);
        $stmt->close();
        return;
    }

    // Добавление новой учетной записи в таблицу users
    $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $username, $password);

    if ($stmt->execute() === TRUE) {
        $id = $stmt->insert_id;
        $response = array(
            "id" => $id,
            "message" => "User created successfully",
            "status" => "success"
        );
    } else {
        $response = array(
            "message" => "Error: " . $stmt->error,
            "status" => "error"
        );
    }

    echo json_encode($response);
    $stmt->close();
}


function handlePutRequest($conn) {
    $input = json_decode(file_get_contents('php://input'), true);
    $id = $input['id'];
    $name = $input['name'];
    $response = array();

    $sql = "UPDATE greetings SET name = '$name' WHERE id = '$id'";
    if ($conn->query($sql) === TRUE) {
        $response = array(
            "message" => "Record updated successfully",
            "status" => "success"
        );
    } else {
        $response = array(
            "message" => "Error: " . $conn->error,
            "status" => "error"
        );
    }

    echo json_encode($response);
}

function handleDeleteRequest($conn) {
    $input = json_decode(file_get_contents('php://input'), true);
    $id = $input['id'];
    $response = array();

    $sql = "DELETE FROM greetings WHERE id = '$id'";
    if ($conn->query($sql) === TRUE) {
        // Пересчитываем ID после успешного удаления
        reorderIds($conn);

        $response = array(
            "message" => "Record deleted successfully and IDs reordered",
            "status" => "success"
        );
    } else {
        $response = array(
            "message" => "Error: " . $conn->error,
            "status" => "error"
        );
    }

    echo json_encode($response);
}

function reorderIds($conn) {
    $sql = "
        SET @count = 0;
        UPDATE greetings SET id = @count:= @count + 1;
        ALTER TABLE greetings AUTO_INCREMENT = 1;
    ";
    $conn->multi_query($sql);
}

function handleNotFound($uri) {
    error_log("Current URI: " . $uri);  // Отладочный вывод
    $response = array(
        "message" => "Route not found",
        "status" => "error",
        "current_uri" => $uri,
        "expected_uri" => '/project/api/greeting'
    );

    echo json_encode($response);
}

// Закрываем соединение с базой данных
$conn->close();
?>

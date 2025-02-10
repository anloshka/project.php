<?php
require 'vendor/autoload.php';
use Lcobucci\JWT\Configuration;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signer\Key\InMemory;

$secretKey = 'your_secret_key'; // Замените на ваш секретный ключ
$configuration = Configuration::forSymmetricSigner(
    new Sha256(),
    InMemory::plainText($secretKey)
);

function generateToken($username) {
    global $configuration;
    $now = new DateTimeImmutable();
    $token = $configuration->builder()
        ->issuedBy('http://localhost') // Издатель токена
        ->permittedFor('http://localhost') // Аудитория токена
        ->issuedAt($now) // Время выпуска токена
        ->expiresAt($now->modify('+1 hour')) // Время истечения токена
        ->withClaim('username', $username) // Добавляем данные пользователя
        ->getToken($configuration->signer(), $configuration->signingKey());

    return $token->toString();
}

function validateToken() {
    global $configuration;

    // Получаем заголовок Authorization
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (!$authHeader || strpos($authHeader, 'Bearer ') !== 0) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(["message" => "Bearer token required"]);
        exit;
    }

    $tokenStr = substr($authHeader, 7);

    try {
        $token = $configuration->parser()->parse($tokenStr);
        assert($token instanceof Token\Plain);

        $clock = new SystemClock(new \DateTimeZone('UTC'));
        $constraints = [
            new SignedWith($configuration->signer(), $configuration->verificationKey()),
            new ValidAt($clock) // Используем ValidAt
        ];

        $constraints = array_merge($configuration->validationConstraints(), $constraints);

        $validator = $configuration->validator();

        if (!$validator->validate($token, ...$constraints)) {
            header('HTTP/1.1 401 Unauthorized');
            echo json_encode(["message" => "Invalid token"]);
            exit;
        }

        // Токен действителен
        return $token;
    } catch (\Exception $e) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(["message" => "Invalid token", "error" => $e->getMessage()]);
        exit;
    }
}

function handleLoginRequest($conn) {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'];
    $password = $input['password'];

    // Подготовка SQL-запроса для проверки существования пользователя
    $sql = "SELECT * FROM users WHERE username = ? AND password = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        // Генерация токена, если пользователь существует
        $token = generateToken($username);
        echo json_encode(array("token" => $token));
    } else {
        // Возвращение сообщения об ошибке, если учетные данные неверны
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(array("message" => "Invalid login credentials"));
    }
    $stmt->close();
}

function handleRefreshTokenRequest() {
    $token = validateToken();
    $newToken = refreshToken($token);
    if ($newToken) {
        echo json_encode(array("token" => $newToken));
    } else {
        header('HTTP/1.1 400 Bad Request');
        echo json_encode(array("message" => "Token not eligible for refresh"));
    }
}

function refreshToken($token) {
    global $configuration;
    $now = new DateTimeImmutable();
    $expiresAt = $token->claims()->get('exp');
    if ($now > $expiresAt->modify('-10 minutes')) {
        $username = $token->claims()->get('username');
        return generateToken($username);
    }
    return null;
}
?>

<?php
// Конфигурация базы данных
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'root'); 
define('DB_NAME', 'my_database');

// Подключение к базе данных
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// Проверка подключения
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>


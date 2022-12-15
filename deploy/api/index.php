<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Serializer;

require  __DIR__ . '/../src/Client.php';
require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../bootstrap.php';
 
const JWT_SECRET = "makey1234567";

$encoders = array(new JsonEncoder());
$normalizers = array(new ObjectNormalizer());
$serializer = new Serializer($normalizers, $encoders);

$app = AppFactory::create();

$app->post('/api/login', function (Request $request, Response $response) {
    $body = (array)$request->getParsedBody();
    $login = $body['login'];
    $password = $body['password'];

    $jwt = createJWT($login, $password);
    return $response->withHeader("Authorization", "Bearer $jwt");
});

function createJWT($login, $password) : string
{
    $issuedAt = time();
    $expirationTime = $issuedAt + 600;
    $payload = array(
        'login' => $login,
        'password' => $password,
        'iat' => $issuedAt,
        'exp' => $expirationTime
    );

    return JWT::encode($payload, JWT_SECRET);
}

$app->get('/api/products', function (Request $request, Response $response) use ($serializer) {
    global $entityManager;
    $productRepository = $entityManager->getRepository('Product');
    $products = $productRepository->findAll();

    $json = $serializer->serialize($products, 'json');
    $response->getBody()->write($json);
    return $response;
});

$app->get('/api/product/{id}', function (Request $request, Response $response, $args) use ($serializer) {
    global $entityManager;
    $id = $args ['id'];
    $productRepository = $entityManager->getRepository('Product');
    $product = $productRepository->find($id);

    $json = $serializer->serialize($product, 'json');
    $response->getBody()->write($json);
    return $response;
});

$app->post('/api/register', function (Request $request, Response $response) use ($serializer) {
    global $entityManager;
    $body = (array)$request->getParsedBody();
    $client = createClientFromBody($body);
    $entityManager->persist($client);
    $entityManager->flush();

    $client->setPassword(null);
    $json = $serializer->serialize($client, 'json');
    $response->getBody()->write($json);
    return $response;
});

function createClientFromBody($body): Client {
    $client = new Client();
    $client->setFirstname($body['firstname']);
    $client->setLastname ($body['lastname']);
    $client->setEmail($body['email']);
    $client->setLogin($body['login']);
    $client->setPassword(password_hash($body['password'], PASSWORD_DEFAULT));
    $client->setPhone($body['phone']);
    $client->setLocale($body['locale']);
    $client->setAddress($body['address']);
    $client->setCity($body['city']);
    $client->setZip($body['zip']);
    $client->setCountry($body['country']);
    $client->setCivility($body['civility']);
    return $client;
}

$options = [
    "attribute" => "token",
    "header" => "Authorization",
    "regexp" => "/Bearer\s+(.*)$/i",
    "secure" => false,
    "algorithm" => ["HS256"],
    "secret" => JWT_SECRET,
    "path" => ["/api"],
    "ignore" => ["/api/login", "/api/register"],
    "error" => function ($response) {
        $data = array('ERREUR' => 'Connexion', 'ERREUR' => 'JWT Non valide');
        $response = $response->withStatus(401);
        return $response->withHeader("Content-Type", "application/json")->getBody()->write(json_encode($data));
    }
];

$app->addBodyParsingMiddleware();
$app->add(new Tuupola\Middleware\JwtAuthentication($options));
$app->add(new Tuupola\Middleware\CorsMiddleware([
    "origin" => ["*"],
    "methods" => ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "headers.allow" => ["Authorization", "Content-Type"],
    "headers.expose" => ["Authorization"],
]));

$app->run();
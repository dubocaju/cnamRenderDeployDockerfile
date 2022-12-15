<?php
use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;
date_default_timezone_set('America/Lima');
require_once "vendor/autoload.php";
$isDevMode = true;
$config = Setup::createYAMLMetadataConfiguration(array(__DIR__ . "/config/yaml"), $isDevMode);
$conn = array(
'host' => 'dpg-cedj03kgqg45hta2elbg-a.frankfurt-postgres.render.com',
'driver' => 'pdo_pgsql',
'user' => 'cnam_bxk4_user',
'password' => 'Ub1rNNjdeLKzPY8AWOBHeUb1igawSA72',
'dbname' => 'cnam_bxk4',
'port' => '5432'
);
$entityManager = EntityManager::create($conn, $config);

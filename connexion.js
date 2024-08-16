// db.js

import { createConnection } from 'mysql2';

const connection = createConnection({
    host: 'localhost',
    user: 'root',  // Remplacez par votre nom d'utilisateur MySQL
    password: '',  // Remplacez par votre mot de passe MySQL
    database: 'agencysn',
    port: '3306'

});

connection.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à la base de données:', err);
        return;
    }
    console.log('Connexion à la base de données MySQL réussie!');
});

export default connection;

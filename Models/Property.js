const { Sequelize, DataTypes } = require('sequelize');

// Connexion à la base de données (exemple)
const sequelize = new Sequelize('agencysn', 'root', '', {
    host: 'localhost',
    dialect: 'mysql', 
});

// Définition du modèle Property
const Property = sequelize.define('Property', {
    user_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
    },
    type: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    title: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            len: {
                args: [1, 100],
                msg: "Le titre de la propriété ne doit pas dépasser 100 caractères",
            }
        }
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    price: {
        type: DataTypes.FLOAT,
        allowNull: false,
    },
    address: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    images: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        allowNull: false,
    },
    availability: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    created_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW,
    }
}, {
    timestamps: false, // Si tu ne veux pas que Sequelize gère createdAt et updatedAt
    tableName: 'properties', // Nom de la table dans la base de données
});

module.exports = Property;

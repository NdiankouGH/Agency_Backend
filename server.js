const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const Property = require("./Models/Property");
const path = require("path");
const multer = require("multer");
const { col } = require("sequelize");
const { title } = require("process");
const { SELECT } = require("sequelize/lib/query-types");
const { model } = require("mongoose");

dotenv.config();

const app = express();

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "storage/images/");
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Seules les images sont autorisées"));
  },
  limits: { fileSize: 3000000 }, // limite à 3MB
});

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
};

let db;

async function connectDB() {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log("Connecté à la base de données MySQL.");
  } catch (err) {
    console.error("Erreur de connexion à la base de données:", err);
    process.exit(1);
  }
}

connectDB();
app.use(
  "/storage/images",
  express.static(path.join(__dirname, "storage/images"))
);

app.get("/", (req, res) => {
  res.json({ message: "Bienvenue sur l'API AgencySN" });
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, telephone, password } = req.body;

    if (!name || !email || !telephone || !password) {
      return res.status(400).json({ message: "Tous les champs sont requis" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Format d'email invalide" });
    }

    const [existingUsers] = await db.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existingUsers.length > 0) {
      return res
        .status(400)
        .json({ message: "L'adresse e-mail est déjà utilisée" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO users (name, email, telephone, password) VALUES (?, ?, ?, ?)",
      [name, email, telephone, hashedPassword]
    );

    console.log("Nouvel utilisateur inséré:", { name, email, telephone });
    res.status(201).json({ message: "Inscription réussie" });
  } catch (error) {
    console.error("Erreur lors de l'inscription:", error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Vérification si l'utilisateur existe
    const [users] = await db.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (users.length === 0) {
      return res.status(404).json({ message: "Utilisateur non trouvé" });
    }

    const user = users[0];

    // Vérification du mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Mot de passe incorrect" });
    }

    // Création d'un token JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ message: "Connexion réussie", token });
  } catch (error) {
    console.error("Erreur lors de la connexion:", error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get("/api/protected", authenticateToken, (req, res) => {
  res.json({ message: "Accès autorisé" });
});

app.get("/user", authenticateToken, async (req, res) => {
  try {
    const [users] = await db.execute("SELECT * FROM users where id = ?", [
      req.user.id,
    ]);
    if (users.length === 0) {
      return res.status(404).json({ message: "Utilisateur non trouvé" });
    }

    const user = users[0];
    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      telephone: user.telephone,
    });
  } catch (error) {
    console.error(
      "Erreur lors de la récupération des informations de l'utilisateur:",
      error
    );
    res.status(500).json({ message: "Erreur serveur" });
  }
});
app.get("/verifyToken", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.json({ isValid: false });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.json({ isValid: false });
    }
    // Token est valide, renvoyer les informations de l'utilisateur
    res.json({
      isValid: true,
      user: {
        id: decoded.id,
        username: decoded.name,
        usertelephon: decoded.telephone,
        useremail: decoded.email,
      },
    });
  });
});

app.get("/test-db-connection", async (req, res) => {
  try {
    const [results] = await db.execute("SELECT 1 + 1 AS solution");
    console.log("La solution est:", results[0].solution);

    res.json({ message: "Connexion à la base de données réussie!" });
  } catch (error) {
    console.error("Erreur lors de la requête:", error);
    res
      .status(500)
      .json({ message: "Erreur lors de la requête à la base de données" });
  }
});

//Insertion d'une propriete
app.post(
  "/postProperty",
  authenticateToken,
  upload.array("images", 10),
  async (req, res) => {
    const { user_id, type, title, bedroom, bathroom, description, price, address, availability } =
      req.body;

    const images = req.files;
    const imagePaths = images.map((file) => `images/${file.filename}`);
    const imagePathsJSON = JSON.stringify(imagePaths);
    if (!images || images.length === 0) {
      return res
        .status(400)
        .json({ message: "Au moins une image est requise" });
    }

    try {
      await db.execute(
        "INSERT INTO properties (user_id, type, title,bedroom, bathroom, description, price, address, images, availability, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
        [
          user_id,
          type,
          title,
          parseInt(bedroom),
          parseInt(bathroom),
          description,
          parseFloat(price),
          address,
          imagePathsJSON,
          availability === "true",
        ]
      );
      res.status(201).json({ message: "Propriété créée avec succès" });
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: "Erreur lors de la création de la propriété",
        error: error.message,
      });
    }
  }
);
//Recuperer une propriété par son id
app.get('/properties/:id', async (req, res) => {
    const propertyId = req.params.id;

    try {
        const [propertyResult] = await db.execute(
            "SELECT * FROM properties WHERE id = ?",
            [propertyId]
        );

        if (propertyResult.length === 0) {
            return res.status(404).json({ message: "Propriété non trouvée" });
        }

        const property = propertyResult[0];

        // Si des champs comme les images sont stockés sous forme de chaîne JSON, vous pouvez les analyser ici
        if (property.images) {
            property.images = JSON.parse(property.images);
        }

        res.json(property);
    } catch (error) {
        console.error("Erreur lors de la récupération de la propriété:", error);
        res.status(500).json({ message: "Erreur du serveur" });
    }
});


// Route pour créer un véhicule
app.post(
  "/postVehicle",
  authenticateToken,
  upload.array("images", 10),
  async (req, res) => {
    let {
      user_id,
      type,
      transactionType,
      make,
      model,
      kilometrage,
      transmission,
      fuel,
      color,
      year,
      price,
      description,
      availability,
    } = req.body;
    const images = req.files;

    // Vérification et attribution de valeurs par défaut
    user_id = user_id || null;
    type = type || "";
    transactionType = transactionType | '';
    make = make || "";
    model = model || "";
    kilometrage = kilometrage || null;
    transmission = transmission || "";
    fuel = fuel || "";
    color = color || "";
    year = year || null;
    price = price ? parseFloat(price) : null;
    description = description || "";
    availability = availability || "Non-Disponible";

    // Vérification des images
    if (!images || images.length === 0) {
      return res
        .status(400)
        .json({ message: "Au moins une image est requise" });
    }

    const imagePaths = images.map((file) => `images/${file.filename}`);
    const imagePathsJSON = JSON.stringify(imagePaths);

    try {
      await db.execute(
        "INSERT INTO vehicles (user_id, type, transactionType make, model,  year,kilometrage, transmission, fuel, color, price, description, images, availability, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
        [
          user_id,
          type,
          transactionType,
          make,
          model,
          year,
          kilometrage,
          transmission,
          fuel,
          color,
          price,
          description,
          imagePathsJSON,
          availability,
        ]
      );
      res.status(201).json({ message: "Véhicule créé avec succès" });
    } catch (error) {
      console.error("Erreur lors de l'insertion:", error);
      res
        .status(500)
        .json({
          message: "Erreur lors de la création du véhicule",
          error: error.message,
        });
    }
  }
);

//

app.post(
  "/postEquipement",
  authenticateToken,
  upload.array("images", 10),
  async (req, res) => {
    const { user_id, type, transactionType, title, state, brand, model, description, price, availability } = req.body;
    const images = req.files;

    if (!images || images.length === 0) {
      return res
        .status(400)
        .json({ message: "Au moins une image est requise" });
    }

    const imagePaths = images.map((file) => `images/${file.filename}`);
    const imagePathsJSON = JSON.stringify(imagePaths);

    try {
      await db.execute(
        "INSERT INTO equipements (user_id, type, transactionType, title,  state, brand, model, description, price, images, availability, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
        [
          user_id,
          type,
          transactionType,
          title,
          state, 
          brand,
          model,
          description,
          parseFloat(price),
          imagePathsJSON,
          availability,
        ]
      );

      res.status(201).json({ message: "Équipement créé avec succès" });
    } catch (error) {
      console.error("Erreur lors de l'insertion:", error);
      res
        .status(500)
        .json({
          message: "Erreur lors de la création de l'équipement",
          error: error.message,
        });
    }
  }
);

// Route pour les propriete annoncees par l'utilisateur
app.get("/getUserProperties", authenticateToken, async (req, res) => {
  try {
    const [userProperties] = await db.execute(
      "SELECT id, user_id, title, bedroom, bathroom, type, description, price, address, images, created_at FROM properties WHERE user_id = ?",
      [req.user.id]
    );

    if (userProperties.length === 0) {
      return res.status(200).json([]);
    }

    const properties = userProperties.map((property) => ({
      id: property.id,
      user_id: property.user_id,
      title: property.title,
      bedroom: property.bedroom,
      bathroom: property.bathroom,
      type: property.type,
      description: property.description,
      price: property.price,
      address: property.address,
      images: JSON.parse(property.images),
      created_at: property.created_at,
    }));

    res.json(properties);
  } catch (error) {
    console.error(
      "Erreur lors de la récupération des propriétés de l'utilisateur:",
      error
    );
    res
      .status(500)
      .json({
        message: "Erreur serveur lors de la récupération des propriétés",
      });
  }
});



//Route pour supprimer une propriete par son id
app.delete('/deletePropertyById/:id', authenticateToken, async(req, res) => {
  const propertyId = req.params.id;
  const userId = req.user.id;
  try {
    const [property] = await db.execute("SELECT * FROM properties WHERE id = ? AND user_id = ?", 
      [propertyId, userId]
    );
    if (property.length === 0) {
      return res.status(404).json({ message: "Propriété non trouvée ou vous n'avez pas les droits pour la supprimer" });
    }
    const [result] = await db.execute(
      "DELETE FROM properties WHERE id = ?",
      [propertyId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "La propriété n'a pas pu être supprimée" });
    }

    res.status(200).json({ message: "Propriété supprimée avec succès" });
  } catch (error) {
    console.error(
      "Erreur lors de la suppression de la propriété de l'utilisateur:",
      error
    );
    res.status(500).json({ message: "Erreur serveur lors de la suppression de la propriété" });
  }
});
// Route pour les véhicules annoncés par l'utilisateur
app.get("/getUserVehicles", authenticateToken, async (req, res) => {
  try {
    const [userVehicles] = await db.execute(
      "SELECT * FROM vehicles WHERE user_id = ?",
      [req.user.id]
    );

    if (userVehicles.length === 0) {
      return res.status(404).json({ message: "Vous n'avez publié aucun véhicule" });
    }

    const vehicles = userVehicles.map((userVehicle) => ({
      id: userVehicle.id,
      user_id: req.user.id,
      title: userVehicle.title, // Assurez-vous que le champ "title" existe dans la base de données
      type: userVehicle.type,
      make: userVehicle.make,
      model: userVehicle.model,
      year: userVehicle.year,
      kilometrage: userVehicle.kilometrage,
      transmission: userVehicle.transmission,
      fuel: userVehicle.fuel,
      color: userVehicle.color,
      price: userVehicle.price,
      description: userVehicle.description,
      images: userVehicle.images ? JSON.parse(userVehicle.images) : [],
      availability: userVehicle.availability,
      created_at: userVehicle.created_at,
    }));

    res.json(vehicles);
  } catch (error) {
    console.error('Erreur serveur:', error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});


// route pour supprimer un vehicule 
app.delete('/deleteVehicleById/:id', authenticateToken, async (req, res) => {
  const vehicleId = req.params.id;
  const userId = req.user.id;
  try {
    const [rows] = await db.execute(
      "SELECT * FROM vehicles WHERE id = ? AND user_id = ?", 
      [vehicleId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Véhicule non trouvé ou vous n'avez pas les droits pour le supprimer" });
    }

    const [result] = await db.execute(
      "DELETE FROM vehicles WHERE id = ?", 
      [vehicleId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Le véhicule n'a pas pu être supprimé" });
    }

    res.status(200).json({ message: "Véhicule supprimé avec succès" });
  } catch (error) {
    console.error("Erreur lors de la suppression du véhicule de l'utilisateur:", error);
    res.status(500).json({ message: "Erreur serveur lors de la suppression du véhicule" });
  }
});



//Route pour les equipements annonces par l'utilisateur
app.get("/getUserEquipements", authenticateToken, async (req, res) => {
  try {
    const [userEquipments] = await db.execute(
      "SELECT id, user_id, title,   type, state, brand , model, description, price, images, created_at FROM equipements WHERE user_id = ?",
      [req.user.id]
    );

    if (userEquipments.length === 0) {
      return res.status(200).json([]);
    }

    const equipments = userEquipments.map((equipment) => ({
      id: equipment.id,
      user_id: req.user_id,
      title: equipment.title,
      type: equipment.type,
      state: equipment.state,
      brand: equipment.brand,
      model: equipment.model,
      description: equipment.description,
      price: equipment.price,
      images: JSON.parse(equipment.images),
      created_at: equipment.created_at,
    }));

    res.json(equipments);
  } catch (error) {
    console.error(
      "Erreur lors de la récupération des équipements de l'utilisateur:",
      error
    );
    res
      .status(500)
      .json({
        message: "Erreur serveur lors de la récupération des équipements",
      });
  }
});
// route pour supprimer un équipement
app.delete('/deleteEquipmentById/:id', authenticateToken, async (req, res) => { 
  const equipmentId = req.params.id;
  const userId = req.user.id;

  try {
      const [equipment] = await db.execute(
          "SELECT * FROM equipements WHERE id = ? AND user_id = ?", 
          [equipmentId, userId]
      );

      if (equipment.length === 0) {
          return res.status(404).json({ message: "Équipement non trouvé ou vous n'avez pas les droits pour le supprimer" });
      }

      const [result] = await db.execute("DELETE FROM equipements WHERE id = ?", [equipmentId]);

      if (result.affectedRows === 0) {
          return res.status(404).json({ message: "L'équipement n'a pas pu être supprimé" });
      }

      res.status(200).json({ message: "Équipement supprimé avec succès" });

  } catch (error) {
      console.error("Erreur lors de la suppression de l'équipement de l'utilisateur:", error);
      res.status(500).json({ message: "Erreur serveur lors de la suppression de l'équipement" });
  }
});


// recuperer l'ensemble des proprietes
app.get("/listProperties", async (req, res) => {
  try {
    const [userProperties] = await db.execute(
      `SELECT properties.id, properties.user_id, properties.title, properties.bedroom, properties.bathroom, properties.type, properties.transactionType, properties.description, properties.price, properties.address, properties.images, properties.created_at, users.name, users.email, users.telephone 
       FROM properties 
       JOIN users ON properties.user_id = users.id`
    );

    if (userProperties.length === 0) {
      console.log("Aucune propriété trouvée");
      return res.status(200).json([]);
    }

    const properties = userProperties.map((property) => ({
      id: property.id,
      user_id: property.user_id,
      title: property.title,
      bedroom: property.bedroom,
      bathroom: property.bathroom,
      type: property.type,
      transactionType: property.transactionType,
      description: property.description,
      price: property.price,
      address: property.address,
      images: JSON.parse(property.images),
      availability: property.availability,
      created_at: property.created_at,
      user: {
        name: property.name,
        email: property.email,
        telephone: property.telephone,
      },
    }));

    res.json(properties);
  } catch (error) {
    console.error(
      "Erreur lors de la récupération des propriétés de l'utilisateur:",
      error
    );
    res
      .status(500)
      .json({
        message: "Erreur serveur lors de la récupération des propriétés",
      });
  }
});

// Route pour récupérer tous les véhicules
app.get("/getAllVehicles", async (req, res) => {
  try {
    const [vehicleTab] = await db.execute(
      `SELECT * FROM vehicles JOIN users ON vehicles.user_id = users.id`
    );
    if (vehicleTab.length === 0) {
      console.log("Aucun véhicule trouvé dans la base de données");
      return res.status(200).json([]);
    }
    const vehicles = vehicleTab.map((vehicle) => ({
      id: vehicle.id,
      user_id: vehicle.user_id,
      title:vehicle.title,
      make: vehicle.make,
      model: vehicle.model,
      year: vehicle.year,
      kilometrage: vehicle.kilometrage,
      transmission: vehicle.transmission,
      fuel: vehicle.fuel,
      color: vehicle.color,
      price: vehicle.price,
      description: vehicle.description,
      availability: vehicle.availability,
      images: JSON.parse(vehicle.images),
      created_at: vehicle.created_at,
      user: {
        name: vehicle.name,
        email: vehicle.email,
        telephone: vehicle.telephone,
      },
    }));

    res.json(vehicles);
  } catch (error) {
    res.status(500).send("Erreur du serveur");
  }
});

app.get('/listEquipements', async (req, res) =>{

    try {
      [equipmentTab] = await db.execute("SELECT * FROM equipements JOIN users ON equipements.user_id = users.id")

      if (equipmentTab.length === 0) {
       // console.log("Aucun équipement trouvé dans la base de données");
        return res.status(200).json([]); 
      }
  
      const equipements = equipmentTab.map((equipement) => ({
        id: equipement.id,
        user_id: equipement.user_id,
        title: equipement.title,
        description: equipement.description,
        availability: equipement.availability,
        images: JSON.parse(equipement.images),
        created_at: equipement.created_at,
  
        user: {
          name: equipement.name,
          email: equipement.email,
          telephone: equipement.telephone,
        },
      }));
  
      res.json(equipements);
  
    } catch (error) {
      console.log("Erreur lors de la récupération des equipements:", error);
    res.status(500).send("Erreur du serveur");
    }
});


// Update des propriétés, des vehicules et des equipements
//Update propriétés


app.put('/updateProperty/:id', authenticateToken, upload.array("images", 10), async (req, res) => {
  const propertyId = req.params.id;
  const { title, type, transactionType, price, address, description, availability, imagesToDelete } = req.body;
  const newImages = req.files;

  if (!title || !price || !address) {
    return res.status(400).json({ message: "Title, price, and address are required" });
  }

  try {
    // Vérifier si la propriété existe
    const [existingProperty] = await db.execute("SELECT * FROM properties WHERE id = ?", [propertyId]);
    
    if (existingProperty.length === 0) {
      return res.status(404).json({ message: "Property not found" });
    }

    // Gérer les images
    let currentImages = JSON.parse(existingProperty[0].images || '[]');
    const imagesToDeleteArray = JSON.parse(imagesToDelete || '[]');

    // Supprimer les images demandées
    currentImages = currentImages.filter(img => !imagesToDeleteArray.includes(img));

    // Ajouter les nouvelles images
    if (newImages && newImages.length > 0) {
      const newImagePaths = newImages.map((file) => `images/${file.filename}`);
      currentImages = [...currentImages, ...newImagePaths];
    }

    const imagePathsJSON = JSON.stringify(currentImages);

    // Mettre à jour la propriété
    const updateProperty = await db.execute(
      "UPDATE properties SET title = ?, type = ?, transactionType = ?, price = ?, address = ?, description = ?, availability = ?, images = ? WHERE id = ?",
      [title, type, transactionType, price, address, description, availability, imagePathsJSON, propertyId]
    );

    if (updateProperty[0].affectedRows > 0) {
      // Supprimer physiquement les fichiers d'image si nécessaire
      imagesToDeleteArray.forEach(img => {
        const filePath = path.join(__dirname, 'storage', img);
        fs.unlink(filePath, err => {
          if (err) console.error(`Failed to delete image: ${img}`, err);
        });
      });

      res.status(200).json({ message: "Property updated successfully" });
    } else {
      res.status(500).json({ message: "Failed to update property" });
    }
  } catch (error) {
    console.error("Error updating property:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//Update d'un vehicle
app.put('/updateVehicle/:id', authenticateToken, upload.array("images", 10), async (req, res) => {
  const vehicleId = req.params.id;
  const { title, type, transactionType, make, model, year, kilometrage, transmission, fuel, color, price, description, availability, imagesToDelete } = req.body;
  const newImages = req.files;

  try {
    // Vérifier si le véhicule existe
    const [existingVehicle] = await db.execute("SELECT * FROM vehicles WHERE id = ?", [vehicleId]);
    if (existingVehicle.length === 0) {
      return res.status(404).json({ message: 'Vehicle not found' });
    }

    // Gérer les images
    let currentImages = JSON.parse(existingVehicle[0].images || '[]');
    const imagesToDeleteArray = JSON.parse(imagesToDelete || '[]');

    // Supprimer les images demandées
    currentImages = currentImages.filter(img => !imagesToDeleteArray.includes(img));

    // Ajouter les nouvelles images
    if (newImages && newImages.length > 0) {
      const newImagePaths = newImages.map((file) => `images/${file.filename}`);
      currentImages = [...currentImages, ...newImagePaths];
    }

    const imagePathsJSON = JSON.stringify(currentImages);

    // Mettre à jour le véhicule
    const updateVehicle = await db.execute(
      "UPDATE vehicles SET title = ?, type = ?, transactionType = ?, make = ?, model = ?, year = ?, kilometrage = ?, transmission = ?, fuel = ?, color = ?, price = ?, description = ?, images = ?, availability = ? WHERE id = ?",
      [title, type, transactionType, make, model, year, kilometrage, transmission, fuel, color, price, description, imagePathsJSON, availability, vehicleId]
    );

    if (updateVehicle[0].affectedRows > 0) {
      // Supprimer physiquement les fichiers d'image si nécessaire
      imagesToDeleteArray.forEach(img => {
        const filePath = path.join(__dirname, 'storage', img);
        fs.unlink(filePath, err => {
          if (err) console.error(`Failed to delete image: ${img}`, err);
        });
      });

      res.status(200).json({ message: "Vehicle updated successfully" });
    } else {
      res.status(500).json({ message: "Failed to update vehicle" });
    }
  } catch (error) {
    console.error("Error updating vehicle:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//Update d'un equipement
app.put('/updateEquipment/:id', authenticateToken, upload.array("images", 10), async (req, res) => {
  const equipmentId = req.params.id;
  const { title, type, transactionType, state, brand, model, price, description, availability, imagesToDelete } = req.body;
  const newImages = req.files;

  try {
    // Vérifier si l'équipement existe
    const [existingEquipment] = await db.execute("SELECT * FROM equipements WHERE id = ?", [equipmentId]);
    if (existingEquipment.length === 0) {
      return res.status(404).json({ message: 'Equipment not found' });
    }

    // Gérer les images
    let currentImages = JSON.parse(existingEquipment[0].images || '[]');
    const imagesToDeleteArray = JSON.parse(imagesToDelete || '[]');

    // Supprimer les images demandées
    currentImages = currentImages.filter(img => !imagesToDeleteArray.includes(img));

    // Ajouter les nouvelles images
    if (newImages && newImages.length > 0) {
      const newImagePaths = newImages.map((file) => `images/${file.filename}`);
      currentImages = [...currentImages, ...newImagePaths];
    }

    const imagePathsJSON = JSON.stringify(currentImages);

    // Mettre à jour l'équipement
    const updateEquipment = await db.execute(
      "UPDATE equipements SET title = ?, type = ?, transactionType = ?, state = ?, brand = ?, model = ?, price = ?, description = ?, images = ?, availability = ? WHERE id = ?",
      [title, type, transactionType, state, brand, model, price, description, imagePathsJSON, availability, equipmentId]
    );

    if (updateEquipment[0].affectedRows > 0) {
      // Supprimer physiquement les fichiers d'image si nécessaire
      imagesToDeleteArray.forEach(img => {
        const filePath = path.join(__dirname, 'storage', img);
        fs.unlink(filePath, err => {
          if (err) console.error(`Failed to delete image: ${img}`, err);
        });
      });

      res.status(200).json({ message: "Equipment updated successfully" });
    } else {
      res.status(500).json({ message: "Failed to update equipment" });
    }
  } catch (error) {
    console.error("Error updating equipment:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


const PORT = process.env.PORT || 8000;
app.listen(PORT, () =>
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
);

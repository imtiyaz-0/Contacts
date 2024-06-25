const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const Contact = require('./models/Contact');
require('dotenv').config();


const app = express();
const port = process.env.PORT || 3001;

app.use(bodyParser.json());

mongoose.connect(
  process.env.MONGO_URL
)
.then(() => console.log("DB Connection Successful"))
.catch(err => console.log(err.message));

const duser = { username: 'saltman', password: 'oai1122' };
const JWT_SECRET = 'as2809';

const algorithm = 'aes-256-ctr';
const secretKey = "ThisIsASecureSecretKey123!@#asdf";
const iv = Buffer.from('1234567890123456', 'utf8');  // Fixed IV

const encrypt = (text) => {
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

const decrypt = (hash) => {
  const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
  let decrypted = decipher.update(hash, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};


const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(403).json({ error: 'No token present' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(403).json({ error: 'No token present' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to authenticate the provided token' });
    }

    req.userId = decoded.username; 
    next();
  });
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === duser.username && password === duser.password) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid user' });
  }
});

app.post('/contacts', verifyToken, (req, res) => {
  const { name, phone, email, linkedin, twitter } = req.body;

  if (!name || !phone) {
    return res.status(400).json({ error: 'Name and phone are required' });
  }

  const newContact = new Contact({
    id: uuidv4(),
    name: encrypt(name),
    phone: encrypt(phone.toString()),
    email: email ? encrypt(email) : null,
    linkedin: linkedin ? encrypt(linkedin) : null,
    twitter: twitter ? encrypt(twitter) : null
  });

  newContact.save()
    .then(contact => res.json({ message: 'Contact created successfully', contact }))
    .catch(err => res.status(500).json({ error: 'Failed to create contact', err }));
});

app.put('/contacts', verifyToken, async (req, res) => {
  const { name, email, linkedin, twitter } = req.body;

  try {
    const contact = await Contact.findOne({ name: encrypt(name) });

    if (!contact) {
      return res.status(404).json({ error: 'No such contact' });
    }

    if (email) contact.email = encrypt(email);
    if (linkedin) contact.linkedin = encrypt(linkedin);
    if (twitter) contact.twitter = encrypt(twitter);

    const updatedContact = await contact.save();
    res.json({ message: 'Contact updated successfully', contact: updatedContact });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update contact', err });
  }
});

app.post('/search', verifyToken, async (req, res) => {
  const { search_token } = req.body;

  try {
    const contacts = await Contact.find({});

    const results = contacts.filter(contact => decrypt(contact.name).includes(search_token))
      .map(contact => ({
        id: contact.id,
        name: decrypt(contact.name),
        phone: decrypt(contact.phone),
        email: contact.email ? decrypt(contact.email) : null,
        linkedin: contact.linkedin ? decrypt(contact.linkedin) : null,
        twitter: contact.twitter ? decrypt(contact.twitter) : null
      }));

    if (results.length === 0) {
      return res.status(404).json({ error: 'No contacts found' });
    }

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Failed to search contacts', err });
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

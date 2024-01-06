const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const uri = "mongodb+srv://Ahcong29:Faiz29901@assignmentbenr3433.hfietam.mongodb.net/";

const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Welcome to Achong server',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });

  app.get('/', (req, res) => {
    res.send('Server Group 26 Information Security');
  });

  /**
 * @swagger
 * /registerAdmin:
 *   post:
 *     summary: Register an admin
 *     description: Register a new admin with username, password, name, email, phoneNumber, and role
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [Admin]
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *               - role
 *     responses:
 *       '200':
 *         description: Admin registered successfully
 *       '400':
 *         description: Username already registered
 */
  
  app.post('/registerAdmin', async (req, res) => {
    let data = req.body;
    res.send(await registerAdmin(client, data));
  });

  /**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Login as admin
 *     description: Authenticate and log in as admin with username and password, and receive a token
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the admin
 *               password:
 *                 type: string
 *                 description: The password of the admin
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Admin login successful, provides a token
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginAdmin', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });
    
  /**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Login as a security user
 *     description: Login as a security user with username and password
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security user
 *               password:
 *                 type: string
 *                 description: The password of the security user
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful
 *       '401':
 *         description: Unauthorized - Invalid username or password
 */
  app.post('/loginSecurity', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  /**
 * @swagger
 * /registerSecurity:
 *   post:
 *     summary: Register a new security user
 *     description: Register a new security user with username, password, name, email, and phoneNumber
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security
 *               password:
 *                 type: string
 *                 description: The password of the security
 *               name:
 *                 type: string
 *                 description: The name of the security
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the security
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the security
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Security user registered successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */

  app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });


  /**
 * @swagger
 * /readAdmin:
 *   get:
 *     summary: Read admin data
 *     description: Retrieve admin data using a valid token obtained from loginAdmin
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Admin data retrieval successful
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with admin access
 */
  app.get('/readAdmin', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

    /**
 * @swagger
 * /deleteSecurity/{username}:
 *   delete:
 *     summary: Delete a security user by username
 *     description: Delete a security user by username with a valid token obtained from the readAdmin endpoint
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username of the security user to be deleted
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Security user deleted successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Security user not found
 */
app.delete('/deleteSecurity/:username', verifyToken, async (req, res) => {
    let data = req.user;
    let usernameToDelete = req.params.username;
    res.send(await deleteSecurityUser(client, data, usernameToDelete));
});

  /**
 * @swagger
 * /readSecurity:
 *   get:
 *     summary: Read security user data
 *     description: Read security user data with a valid token obtained from the loginSecurity endpoint
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Security user data retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Security user not found
 */
  app.get('/readSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

    
    /**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register a new host
 *     description: Register a new host with username, password, name, email, and phoneNumber
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *               name:
 *                 type: string
 *                 description: The name of the host
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the host
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the host
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Host registered successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */

app.post('/registerHost', verifyToken, async (req, res) => {
    let data = req.user;
    let hostData = req.body;
    res.send(await registerHost(client, data, hostData));
});

    /**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Login as host
 *     description: Authenticate and log in as host with username and password, and receive a token
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Host login successful, provides a token
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post('/loginHost', async (req, res) => {
  let data = req.body;
  res.send(await loginHost(client, data));
});

     /**
 * @swagger
 * /issuePass:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Issue a new visitor pass with a valid token obtained from the loginSecurity endpoint
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               visitorUsername:
 *                 type: string
 *                 description: The username of the visitor for whom the pass is issued
 *               passDetails:
 *                 type: string
 *                 description: Additional details for the pass (optional)
 *             required:
 *               - visitorUsername
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully, returns a unique pass identifier
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Visitor not found
 */
    app.post('/issuePass', verifyToken, async (req, res) => {
        let data = req.user;
        let passData = req.body;
        res.send(await issuePass(client, data, passData));
    });

/**
 * @swagger
 * /retrievePass/{passIdentifier}:
 *   get:
 *     summary: Retrieve visitor pass details
 *     description: Retrieve pass details for a visitor using the pass identifier
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique pass identifier
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Visitor pass details retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */
    app.get('/retrievePass/:passIdentifier', verifyToken, async (req, res) => {
        let data = req.user;
        let passIdentifier = req.params.passIdentifier;
        res.send(await retrievePass(client, data, passIdentifier));
    });
    
    /**
 * @swagger
 * /readHost:
 *   get:
 *     summary: Read host data
 *     description: Retrieve host data with a valid token obtained from the loginAdmin endpoint
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Host data retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Host not found
 */
app.get('/readHost', verifyToken, async (req, res) => {
  let data = req.user;
  res.send(await readHost(client, data));
});

  
}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'faizpass',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

//Function to register admin
async function registerAdmin(client, data) {
  data.password = await encryptPassword(data.password);
  
  const existingUser = await client.db("assigment").collection("Admin").findOne({ username: data.username });
  if (existingUser) {
    return 'Username already registered';
  } else {
    const result = await client.db("assigment").collection("Admin").insertOne(data);
    return 'Admin registered';
  }
}


//Function to login
async function login(client, data) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const usersCollection = client.db("assigment").collection("Users");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the regular user
    match = await usersCollection.findOne({ username: data.username });
  }

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      console.log(output(match.role));
      return "\nToken for " + match.name + ": " + token;
    }
     else {
      return "Wrong password";
    }
  } else {
    return "User not found";
  }
}



//Function to encrypt password
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds); 
  return hash 
}


//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}


//Function to register security and visitor
async function register(client, data, mydata) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const usersCollection = client.db("assigment").collection("Users");

  const tempAdmin = await adminCollection.findOne({ username: mydata.username });
  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempUser = await usersCollection.findOne({ username: mydata.username });

  if (tempAdmin || tempSecurity || tempUser) {
    return "Username already in use, please enter another username";
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      visitors: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await usersCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      
      Security: data.username,
      company: mydata.company,
      vehicleNumber: mydata.vehicleNumber,
      icNumber: mydata.icNumber,
      phoneNumber: mydata.phoneNumber,
      role: "Visitor",
      records: [],
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { visitors: mydata.username } }
    );

    return "Visitor registered successfully";
  }
}

async function issuePass(client, data, passData) {
  const recordsCollection = client.db('assigment').collection('Records'); // New collection for records

  // Check if the security user has the authority to issue passes
  if (data.role !== 'Host') {
    return 'You do not have the authority to issue passes.';
  }

  // Generate a unique pass identifier (you can use a library or a combination of data)
  const passIdentifier = generatePassIdentifier();

  // Store the pass details in the Passes collection
  const passRecord = {
    passIdentifier: passIdentifier,
    visitorUsername: passData.visitorUsername,
    passDetails: passData.passDetails || '',
    issuedBy: data.username, // Security user who issued the pass
    issueTime: new Date(),
  };

  await client.db('assigment').collection('Passes').insertOne(passRecord);

  // Create a new record in the "records" collection
  const newRecord = {
    visitorUsername: passData.visitorUsername,
    newname: passData.newname,
    passDetail: passData.passDetail,
    // Add any other fields you want to store in the "records" collection
  };

  await recordsCollection.insertOne(newRecord);

  return `Visitor pass issued successfully with pass identifier: ${passIdentifier}`;
}


function generatePassIdentifier() {
  // Implement your logic to generate a unique identifier
  // This can be a combination of timestamp, random numbers, or any other strategy that ensures uniqueness

  const timestamp = new Date().getTime(); // Get current timestamp
  const randomString = Math.random().toString(36).substring(7); // Generate a random string

  // Combine timestamp and random string to create a unique identifier
  const passIdentifier = `${timestamp}_${randomString}`;

  return passIdentifier;
}

// Function to register a new host
async function registerHost(client, data, hostData) {
    const hostCollection = client.db("assigment").collection("Host");

    // Check if the username is already in use
    const existingHost = await hostCollection.findOne({ username: hostData.username });

    if (existingHost) {
        return "Username already in use, please enter another username";
    }

    // Insert the new host document
    const result = await hostCollection.insertOne({
        username: hostData.username,
        password: await encryptPassword(hostData.password),
        name: hostData.name,
        email: hostData.email,
        phoneNumber: hostData.phoneNumber,
    });

    return "Host registered successfully";
}

// Function to retrieve pass details
async function retrievePass(client, data, passIdentifier) {
    const passesCollection = client.db('assigment').collection('Passes');
  
    // Find the pass record using the pass identifier
    const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });
  
    if (!passRecord) {
      return 'Pass not found';
    }

    if (data.role === 'Admin') {
      // If the request is from an admin, include the security user's phone number
      const securityCollection = client.db('assigment').collection('Security');
      const securityUser = await securityCollection.findOne({ username: passRecord.issuedBy });
      
      if (!securityUser) {
        return 'Security user not found';
      }

      // You can customize the response format based on your needs
      return {
        passIdentifier: passRecord.passIdentifier,
        visitorUsername: passRecord.visitorUsername,
        passDetails: passRecord.passDetails,
        issuedBy: passRecord.issuedBy,
        issueTime: passRecord.issueTime,
        securityPhoneNumber: securityUser.phoneNumber,
      };
    } else if (data.role === 'Security' && passRecord.issuedBy !== data.username) {
      // Security users can only retrieve their own pass details
      return 'You are not authorized to retrieve pass details for this pass.';
    } else {
      // For other security users and admin, include basic pass details
      return {
        passIdentifier: passRecord.passIdentifier,
        visitorUsername: passRecord.visitorUsername,
        passDetails: passRecord.passDetails,
        issuedBy: passRecord.issuedBy,
        issueTime: passRecord.issueTime
      };
    }
}



//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).next();
    const Securitys = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
    const Visitors = await client.db('assigment').collection('Users').find({ role: 'Visitor' }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Admins, Securitys, Visitors, Records };
  }

  if (data.role == 'Security') {
    const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
    if (!Security) {
      return 'User not found';
    }

    const Visitors = await client.db('assigment').collection('Users').find({ Security: data.username }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Security, Visitors, Records };
  }

  if (data.role == 'Visitor') {
    const Visitor = await client.db('assigment').collection('Users').findOne({ username: data.username });
    if (!Visitor) {
      return 'User not found';
    }

    const Records = await client.db('assigment').collection('Records').find({ recordID: { $in: Visitor.records } }).toArray();

    return { Visitor, Records };
  }
}

function generatePassIdentifier() {
    // Implement your logic to generate a unique identifier
    // This can be a combination of timestamp, random numbers, or any other strategy that ensures uniqueness
  
    const timestamp = new Date().getTime(); // Get current timestamp
    const randomString = Math.random().toString(36).substring(7); // Generate a random string
  
    // Combine timestamp and random string to create a unique identifier
    const passIdentifier = `${timestamp}_${randomString}`;
  
    return passIdentifier;
}
  


//Function to update data
async function update(client, data, mydata) {
  const usersCollection = client.db("assigment").collection("Users");

  if (mydata.password) {
    mydata.password = await encryptPassword(mydata.password);
  }

  const result = await usersCollection.updateOne(
    { username: data.username },
    { $set: mydata }
  );

  if (result.matchedCount === 0) {
    return "User not found";
  }

  return "Update Successfully";
}

// Function to retrieve pass details along with security phone number
async function retrievePass(client, data, passIdentifier) {
  const passesCollection = client.db('assigment').collection('Passes');
  const securityCollection = client.db('assigment').collection('Security');

  // Check if the security user has the authority to retrieve pass details
  if (data.role !== 'Security') {
    return 'You do not have the authority to retrieve pass details.';
  }

  // Find the pass record using the pass identifier
  const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });

  if (!passRecord) {
    return 'Pass not found or unauthorized to retrieve';
  }

  // Find the security user information using the "issuedBy" field from the pass record
  const securityUser = await securityCollection.findOne({ username: passRecord.issuedBy });

  if (!securityUser) {
    return 'Security user not found';
  }

  // You can customize the response format based on your needs
  return {
    passIdentifier: passRecord.passIdentifier,
    visitorUsername: passRecord.visitorUsername,
    passDetails: passRecord.passDetails,
    issuedBy: passRecord.issuedBy,
    issueTime: passRecord.issueTime,
    securityPhoneNumber: securityUser.phoneNumber,
  };
}


// Function to delete a security user by username
async function deleteSecurityUser(client, data, usernameToDelete) {
    const securityCollection = client.db("assigment").collection("Security");

    // Check if the user making the request is an admin
    if (data.role !== 'Admin') {
        return 'You do not have the authority to delete security users.';
    }

    // Delete security user document
    const deleteResult = await securityCollection.deleteOne({ username: usernameToDelete });

    if (deleteResult.deletedCount === 0) {
        return 'Security user not found';
    }

    return 'Security user deleted successfully';
}


//Function to delete data
async function deleteUser(client, data) {
  const usersCollection = client.db("assigment").collection("Users");
  const recordsCollection = client.db("assigment").collection("Records");
  const securityCollection = client.db("assigment").collection("Security");

  // Delete user document
  const deleteResult = await usersCollection.deleteOne({ username: data.username });
  if (deleteResult.deletedCount === 0) {
    return "User not found";
  }

  // Update visitors array in other users' documents
  await usersCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  // Update visitors array in the Security collection
  await securityCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  return "Delete Successful\nBut the records are still in the database";
}

// Function to log in host and provide a token
async function loginHost(client, data) {
  const hostCollection = client.db("assigment").collection("Host");

  // Find the host user
  const host = await hostCollection.findOne({ username: data.username });

  if (host) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, host.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(host);
      console.log(output('Host'));
      return "\nToken for " + host.name + ": " + token;
    } else {
      return "Wrong password";
    }
  } else {
    return "Host not found";
  }
}

// Function to read host data
async function readHost(client, data) {
  if (data.role !== 'Admin') {
    return 'You do not have the authority to read host data.';
  }

  const hostCollection = client.db('assigment').collection('Host');
  const hosts = await hostCollection.find().toArray();

  if (hosts.length === 0) {
    return 'No hosts found';
  }

  return hosts;
}



//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Visitor\n2)read security and visitor data"
  } else if (data == 'Visitor') {
    return "You are logged in as Visitor\n1)check in\n2)check out\n3)read visitor data\n4)update profile\n5)delete account"
  }
}



//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'faizpass', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}

